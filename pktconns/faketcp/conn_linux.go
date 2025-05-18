//go:build linux
// +build linux

package faketcp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil" // For io.Copy(ioutil.Discard, ...)
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	// "github.com/sagernet/sing-quic/pktconns" // Explicitly ensure this line and the one below are removed or fully commented
)

var (
	errTimeout = errors.New("timeout")
	// FlowIdleTimeout is defined in conn.go
)

// message from NIC
type message struct {
	bts  []byte
	addr net.Addr
}

// tcpFlow information
type tcpFlow struct {
	conn         *net.TCPConn // Associated system TCP connection
	handle       *net.IPConn  // Raw IP socket handle for sending
	seq          uint32       // TCP sequence number
	ack          uint32       // TCP acknowledge number
	ts           time.Time    // Last packet incoming time
	buf          gopacket.SerializeBuffer
	tcpHeader    layers.TCP
	networkLayer gopacket.SerializableLayer // For checksum calculation
}

// linuxFakeTCPConn implements the FakeTCPConn interface for Linux.
type linuxFakeTCPConn struct {
	die     chan struct{}
	dieOnce sync.Once
	logger  logger // Changed to local faketcp.logger

	// Underlying connections
	tcpconn  *net.TCPConn     // For client mode (Dial)
	listener *net.TCPListener // For server mode (Listen)

	handles []*net.IPConn // Raw IP socket handles

	chMessage chan message // Channel for incoming packets

	flowTable map[string]*tcpFlow // Maps remote addr string to tcpFlow
	flowsLock sync.Mutex

	// iptables
	v4iptables *iptables.IPTables
	v4iprule   []string
	v6iptables *iptables.IPTables
	v6iprule   []string

	readDeadline  atomic.Value
	writeDeadline atomic.Value

	opts gopacket.SerializeOptions
}

func init() {
	dialInternal = dialLinux
	listenInternal = listenLinux
}

func newLinuxFakeTCPConn(log logger) *linuxFakeTCPConn { // Changed parameter name and type
	return &linuxFakeTCPConn{
		die:       make(chan struct{}),
		logger:    log, // Assign new parameter
		flowTable: make(map[string]*tcpFlow),
		chMessage: make(chan message, 128), // Increased buffer size
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
	}
}

func (c *linuxFakeTCPConn) lockflow(addr net.Addr, f func(e *tcpFlow)) {
	key := addr.String()
	c.flowsLock.Lock()
	defer c.flowsLock.Unlock()
	e, ok := c.flowTable[key]
	if !ok {
		e = &tcpFlow{
			ts:  time.Now(),
			buf: gopacket.NewSerializeBuffer(),
		}
		c.flowTable[key] = e
		if c.logger != nil {
			c.logger.Debugf("faketcp: new flow created for %s", key)
		}
	}
	f(e)
}

func (c *linuxFakeTCPConn) cleaner() {
	ticker := time.NewTicker(FlowIdleTimeout / 2) // Clean more frequently
	defer ticker.Stop()
	for {
		select {
		case <-c.die:
			return
		case <-ticker.C:
			c.flowsLock.Lock()
			now := time.Now()
			for k, v := range c.flowTable {
				if now.Sub(v.ts) > FlowIdleTimeout {
					if c.logger != nil {
						c.logger.Debugf("faketcp: expiring flow for %s (idle for %v)", k, now.Sub(v.ts))
					}
					if v.conn != nil {
						setTTL(v.conn, 64) // Restore TTL before closing
						v.conn.Close()
					}
					delete(c.flowTable, k)
				}
			}
			c.flowsLock.Unlock()
		}
	}
}

func (c *linuxFakeTCPConn) captureFlow(handle *net.IPConn, localPort int) {
	buf := make([]byte, MaxIPPacketSize) // Use defined constant
	opt := gopacket.DecodeOptions{NoCopy: true, Lazy: true}

	if c.logger != nil {
		c.logger.Debugf("faketcp: starting captureFlow on %s for port %d", handle.LocalAddr(), localPort)
	}

	for {
		select {
		case <-c.die:
			if c.logger != nil {
				c.logger.Debugf("faketcp: stopping captureFlow on %s due to die signal", handle.LocalAddr())
			}
			return
		default:
		}

		// Set a read deadline to allow checking c.die periodically
		// This is important to ensure timely shutdown.
		_ = handle.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, raddr, err := handle.ReadFromIP(buf)

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Expected timeout, loop to check c.die
			}
			if !errors.Is(err, net.ErrClosed) && c.logger != nil { // Don't log ErrClosed excessively
				c.logger.Errorf("faketcp: ReadFromIP error on %s: %v", handle.LocalAddr(), err)
			}
			return // Permanent error or closed
		}

		if n == 0 {
			continue
		}

		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeTCP, opt)
		transportLayer := packet.TransportLayer()
		tcp, ok := transportLayer.(*layers.TCP)
		if !ok {
			if c.logger != nil {
				c.logger.Debugf("faketcp: received non-TCP packet on raw socket from %s", raddr)
			}
			continue
		}

		if int(tcp.DstPort) != localPort {
			continue // Not for us
		}

		srcAddr := &net.TCPAddr{IP: raddr.IP, Port: int(tcp.SrcPort)}
		var isOrphan bool

		c.lockflow(srcAddr, func(flow *tcpFlow) {
			if c.listener != nil && flow.conn == nil { // Server mode, flow not yet associated with an accepted conn
				// This can happen if packets arrive before AcceptTCP establishes the flow.conn
				// Or if it's a SYN for a new connection.
				// For now, we'll let it pass, actual data push depends on PSH flag.
			} else if c.tcpconn != nil && flow.conn == nil { // Client mode, should have flow.conn
				isOrphan = true
				if c.logger != nil {
					c.logger.Debugf("faketcp: client mode, orphan packet from %s (no flow.conn)", srcAddr)
				}
			}

			flow.ts = time.Now()
			if tcp.ACK {
				flow.seq = tcp.Ack
			}
			if tcp.SYN { // Important for server to set initial ack for its SYN-ACK
				flow.ack = tcp.Seq + 1
			}
			if tcp.PSH {
				if flow.ack == tcp.Seq { // Common case: received data in sequence
					flow.ack = tcp.Seq + uint32(len(tcp.Payload))
				} else {
					// Out-of-order or retransmission, don't advance ack blindly based on this packet's seq
					// The actual TCP stack would handle this more gracefully.
					// For faketcp, we might just log it.
					if c.logger != nil {
						c.logger.Debugf("faketcp: PSH packet from %s, seq %d, expected ack %d. Payload len %d",
							srcAddr, tcp.Seq, flow.ack, len(tcp.Payload))
					}
					// If we want to be robust, we might need to buffer out-of-order packets,
					// but that significantly complicates faketcp.
					// For now, if it's PSH and seq matches current ack, update ack.
					// Otherwise, the other side should retransmit if it doesn't get our ACKs.
				}
			}
			flow.handle = handle // Update handle, useful if listening on multiple interfaces
		})

		if !isOrphan && tcp.PSH && len(tcp.Payload) > 0 {
			payloadCopy := make([]byte, len(tcp.Payload))
			copy(payloadCopy, tcp.Payload)
			select {
			case c.chMessage <- message{bts: payloadCopy, addr: srcAddr}:
			case <-c.die:
				return
			default:
				if c.logger != nil {
					c.logger.Warnf("faketcp: chMessage full, dropping packet from %s", srcAddr)
				}
			}
		}
	}
}

func (c *linuxFakeTCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := c.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-deadline:
		return 0, nil, errTimeout
	case <-c.die:
		return 0, nil, io.EOF
	case msg := <-c.chMessage:
		n = copy(p, msg.bts)
		return n, msg.addr, nil
	}
}

func (c *linuxFakeTCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var deadline <-chan time.Time
	if d, ok := c.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-deadline:
		return 0, errTimeout
	case <-c.die:
		return 0, io.EOF
	default:
		rTCPAddr, ok := addr.(*net.TCPAddr)
		if !ok {
			return 0, errors.New("faketcp: WriteTo requires a *net.TCPAddr")
		}

		var localPort int
		if c.tcpconn != nil { // Client mode
			localPort = c.tcpconn.LocalAddr().(*net.TCPAddr).Port
		} else if c.listener != nil { // Server mode
			localPort = c.listener.Addr().(*net.TCPAddr).Port
		} else {
			return 0, errors.New("faketcp: connection not properly initialized (no tcpconn or listener)")
		}

		c.lockflow(rTCPAddr, func(flow *tcpFlow) {
			if flow.handle == nil {
				if c.logger != nil {
					c.logger.Warnf("faketcp: no handle for flow %s, dropping packet", rTCPAddr)
				}
				// This can happen if a flow was created by an incoming packet on one interface,
				// but we are trying to write to it before a system TCP conn is established (server)
				// or if the flow timed out and was partially cleaned.
				err = errors.New("faketcp: no handle for flow")
				n = len(p) // Pretend we wrote it to avoid blocking caller, but it's lost.
				return
			}

			flow.tcpHeader.SrcPort = layers.TCPPort(localPort)
			flow.tcpHeader.DstPort = layers.TCPPort(rTCPAddr.Port)
			// Window size can be somewhat random but large enough.
			// Hysteria uses rand.Read for this.
			var windowBytes [2]byte
			rand.Read(windowBytes[:])
			flow.tcpHeader.Window = binary.BigEndian.Uint16(windowBytes[:]) | 0x8000 // Ensure > 32768

			flow.tcpHeader.Ack = flow.ack
			flow.tcpHeader.Seq = flow.seq
			flow.tcpHeader.PSH = true
			flow.tcpHeader.ACK = true
			flow.tcpHeader.FIN = false
			flow.tcpHeader.SYN = false
			flow.tcpHeader.RST = false
			flow.tcpHeader.URG = false
			flow.tcpHeader.ECE = false
			flow.tcpHeader.CWR = false
			flow.tcpHeader.NS = false

			// Checksum calculation
			var ipLayer gopacket.NetworkLayer
			localIPAddr, ok := flow.handle.LocalAddr().(*net.IPAddr)
			if !ok {
				// This should not happen if flow.handle is valid
				err = errors.New("faketcp: invalid local IPAddr for checksum")
				return
			}

			if rTCPAddr.IP.To4() != nil {
				ipLayer = &layers.IPv4{
					Version:  4,
					TTL:      64, // Standard TTL
					Protocol: layers.IPProtocolTCP,
					SrcIP:    localIPAddr.IP.To4(),
					DstIP:    rTCPAddr.IP.To4(),
				}
			} else if rTCPAddr.IP.To16() != nil {
				ipLayer = &layers.IPv6{
					Version:    6,
					HopLimit:   64, // Standard Hop Limit
					NextHeader: layers.IPProtocolTCP,
					SrcIP:      localIPAddr.IP.To16(),
					DstIP:      rTCPAddr.IP.To16(),
				}
			} else {
				err = errors.New("faketcp: destination IP is neither IPv4 nor IPv6")
				return
			}
			flow.tcpHeader.SetNetworkLayerForChecksum(ipLayer)

			payload := gopacket.Payload(p)
			err = gopacket.SerializeLayers(flow.buf, c.opts, &flow.tcpHeader, payload)
			if err != nil {
				if c.logger != nil {
					c.logger.Errorf("faketcp: SerializeLayers error: %v", err)
				}
				return
			}

			var writtenBytes int
			if c.tcpconn != nil { // Client mode, specific handle from Dial
				writtenBytes, err = flow.handle.Write(flow.buf.Bytes())
			} else { // Server mode, write to specific IP
				writtenBytes, err = flow.handle.WriteToIP(flow.buf.Bytes(), &net.IPAddr{IP: rTCPAddr.IP, Zone: rTCPAddr.Zone})
			}

			if err != nil {
				if c.logger != nil {
					c.logger.Errorf("faketcp: WriteToIP/Write error: %v", err)
				}
				return
			}
			if writtenBytes < len(flow.buf.Bytes()) {
				if c.logger != nil {
					c.logger.Warnf("faketcp: short write, expected %d, got %d", len(flow.buf.Bytes()), writtenBytes)
				}
				// Treat as error or partial success? For packet conn, usually all or nothing.
			}

			flow.seq += uint32(len(p)) // Advance sequence number by payload length
			n = len(p)
		})
		return
	}
}

func (c *linuxFakeTCPConn) Close() error {
	var err error
	c.dieOnce.Do(func() {
		if c.logger != nil {
			c.logger.Infof("faketcp: closing connection")
		}
		close(c.die)

		if c.tcpconn != nil {
			setTTL(c.tcpconn, 64) // Restore TTL
			err = c.tcpconn.Close()
		}
		if c.listener != nil {
			err = c.listener.Close()
			c.flowsLock.Lock()
			for k, v := range c.flowTable {
				if v.conn != nil {
					setTTL(v.conn, 64)
					v.conn.Close()
				}
				delete(c.flowTable, k)
			}
			c.flowsLock.Unlock()
		}

		for _, h := range c.handles {
			h.Close()
		}

		// Delete iptables rules
		if c.v4iptables != nil && len(c.v4iprule) > 0 {
			if e := c.v4iptables.Delete("filter", "OUTPUT", c.v4iprule...); e != nil && c.logger != nil {
				c.logger.Errorf("faketcp: failed to delete IPv4 iptables rule: %v", e)
			} else if c.logger != nil {
				c.logger.Infof("faketcp: IPv4 iptables rule deleted: %v", c.v4iprule)
			}
		}
		if c.v6iptables != nil && len(c.v6iprule) > 0 {
			if e := c.v6iptables.Delete("filter", "OUTPUT", c.v6iprule...); e != nil && c.logger != nil {
				c.logger.Errorf("faketcp: failed to delete IPv6 iptables rule: %v", e)
			} else if c.logger != nil {
				c.logger.Infof("faketcp: IPv6 iptables rule deleted: %v", c.v6iprule)
			}
		}
	})
	return err
}

func (c *linuxFakeTCPConn) LocalAddr() net.Addr {
	if c.tcpconn != nil {
		return c.tcpconn.LocalAddr()
	}
	if c.listener != nil {
		return c.listener.Addr()
	}
	// If multiple handles, which one to return?
	// Typically, the "control" TCP conn's address is most relevant.
	// If no control conn (e.g. listener only on raw sockets), might need to pick one handle.
	if len(c.handles) > 0 {
		return c.handles[0].LocalAddr()
	}
	return nil
}

func (c *linuxFakeTCPConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	return nil // Underlying raw IPConns might not support this directly in a meaningful way for ReadFrom/WriteTo
}

func (c *linuxFakeTCPConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	return nil
}

func (c *linuxFakeTCPConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

func (c *linuxFakeTCPConn) SetDSCP(dscp int) error {
	var lastErr error
	for _, h := range c.handles {
		if err := setDSCPHandle(h, dscp); err != nil {
			lastErr = err
			if c.logger != nil {
				c.logger.Errorf("faketcp: SetDSCP error on handle %s: %v", h.LocalAddr(), err)
			}
		}
	}
	return lastErr
}

func (c *linuxFakeTCPConn) SyscallConn() (syscall.RawConn, error) {
	if len(c.handles) > 0 {
		// This is tricky. Which handle?
		// The Hysteria code returns syscall.RawConn from the net.IPConn.
		// If we have a primary tcpconn or listener, its SyscallConn might be more appropriate
		// if the caller expects to control the "main" socket.
		// However, for raw packet operations, any of the handles could be relevant.
		// Let's return the first handle's RawConn.
		rc, err := c.handles[0].SyscallConn()
		if err != nil && c.logger != nil {
			c.logger.Errorf("faketcp: SyscallConn error on handle %s: %v", c.handles[0].LocalAddr(), err)
		}
		return rc, err
	}
	if c.tcpconn != nil { // Client
		return c.tcpconn.SyscallConn()
	}
	if c.listener != nil { // Server, but listener itself doesn't have one RawConn for all accepted
		return nil, errors.New("faketcp: SyscallConn not available on listener, use specific flow connection")
	}
	return nil, errors.New("faketcp: no available connection for SyscallConn")
}

func dialLinux(network, address string, log logger) (FakeTCPConn, error) { // Changed logger type and name
	raddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, fmt.Errorf("faketcp: ResolveTCPAddr: %w", err)
	}

	conn := newLinuxFakeTCPConn(log) // Use new logger parameter name

	// Dial actual TCP connection (will be TTL=1)
	tcpconn, err := net.DialTCP(network, nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("faketcp: DialTCP: %w", err)
	}
	conn.tcpconn = tcpconn
	if log != nil {
		log.Infof("faketcp: Dialed control TCP to %s from %s", tcpconn.RemoteAddr(), tcpconn.LocalAddr())
	}

	// Create raw IP socket
	var handle *net.IPConn
	if raddr.IP.To4() != nil {
		// For IPv4, DialIP with nil laddr means kernel chooses source IP.
		// We need to ensure it matches the source IP of tcpconn for consistency,
		// though for raw sockets sending to a specific raddr, this is less critical
		// than for listening.
		handle, err = net.DialIP("ip4:tcp", nil, &net.IPAddr{IP: raddr.IP})
	} else {
		handle, err = net.DialIP("ip6:tcp", nil, &net.IPAddr{IP: raddr.IP, Zone: raddr.Zone})
	}
	if err != nil {
		tcpconn.Close()
		return nil, fmt.Errorf("faketcp: DialIP (raw): %w", err)
	}
	conn.handles = append(conn.handles, handle)
	if log != nil {
		log.Infof("faketcp: Raw IP socket opened: %s -> %s", handle.LocalAddr(), raddr)
	}

	// Initialize flow for this connection
	conn.lockflow(tcpconn.RemoteAddr(), func(flow *tcpFlow) {
		flow.conn = tcpconn
		flow.handle = handle // Primary handle for this dialed connection
		// Initial SEQ/ACK are usually learned from the 3-way handshake.
		// For faketcp client, we might need to sniff this or use random initial values.
		// Hysteria's faketcp doesn't explicitly show sniffing for client's initial seq/ack.
		// It seems to learn them from first incoming ACK.
		// Let's assume initial seq can be random, ack will be learned.
		var randBytes [4]byte
		rand.Read(randBytes[:])
		flow.seq = binary.BigEndian.Uint32(randBytes[:])
		// flow.ack will be updated upon receiving first packet from server.
	})

	// Set TTL=1 on the control TCP connection
	if err := setTTL(tcpconn, 1); err != nil {
		handle.Close()
		tcpconn.Close()
		return nil, fmt.Errorf("faketcp: setTTL(1) failed: %w", err)
	}
	if log != nil {
		log.Debugf("faketcp: TTL set to 1 for control TCP %s", tcpconn.RemoteAddr())
	}

	// Setup iptables rule to drop RSTs from kernel for the TTL=1 connection
	var rule []string
	if raddr.IP.To4() != nil {
		ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			log.Warnf("faketcp: failed to init IPv4 iptables: %v. Kernel RSTs might interfere.", err)
		} else {
			conn.v4iptables = ipt
			// Rule to drop packets from our local port to remote, if TTL is 1 (or some other mark)
			// Hysteria's rule is: "-m", "ttl", "--ttl-eq", "1", "-p", "tcp", "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"
			// This drops outgoing packets with TTL 1.
			// We also need to ensure kernel doesn't send RST for incoming packets on the raw socket.
			// The primary defense is that the raw socket "claims" the packet before TCP stack.
			// The TTL=1 trick is for the *outgoing* packets from the *control* tcpconn.
			rule = []string{"-p", "tcp",
				"-s", tcpconn.LocalAddr().(*net.TCPAddr).IP.String(),
				"--sport", fmt.Sprint(tcpconn.LocalAddr().(*net.TCPAddr).Port),
				"-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port),
				"-m", "ttl", "--ttl-eq", "1", // This rule targets the control conn's outgoing packets
				"-j", "DROP"}
			exists, err := ipt.Exists("filter", "OUTPUT", rule...)
			if err != nil {
				log.Warnf("faketcp: failed to check IPv4 iptables rule: %v", err)
			} else if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err != nil {
					log.Warnf("faketcp: failed to append IPv4 iptables rule: %v", err)
				} else {
					conn.v4iprule = rule
					log.Infof("faketcp: IPv4 iptables rule added: %v", rule)
				}
			}
		}
	} else { // IPv6
		ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			log.Warnf("faketcp: failed to init IPv6 iptables: %v. Kernel RSTs might interfere.", err)
		} else {
			conn.v6iptables = ipt
			rule = []string{"-p", "tcp",
				"-s", tcpconn.LocalAddr().(*net.TCPAddr).IP.String(),
				"--sport", fmt.Sprint(tcpconn.LocalAddr().(*net.TCPAddr).Port),
				"-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port),
				"-m", "hl", "--hl-eq", "1",
				"-j", "DROP"}
			exists, err := ipt.Exists("filter", "OUTPUT", rule...)
			if err != nil {
				log.Warnf("faketcp: failed to check IPv6 iptables rule: %v", err)
			} else if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err != nil {
					log.Warnf("faketcp: failed to append IPv6 iptables rule: %v", err)
				} else {
					conn.v6iprule = rule
					log.Infof("faketcp: IPv6 iptables rule added: %v", rule)
				}
			}
		}
	}

	go conn.captureFlow(handle, tcpconn.LocalAddr().(*net.TCPAddr).Port)
	go conn.cleaner()
	go func() { // Discard data from control TCP conn
		io.Copy(ioutil.Discard, tcpconn)
		tcpconn.CloseRead() // Signal that we are done reading
	}()

	return conn, nil
}

func listenLinux(network, address string, log logger) (FakeTCPConn, error) { // Changed logger type and name
	laddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, fmt.Errorf("faketcp: ResolveTCPAddr (listen): %w", err)
	}

	conn := newLinuxFakeTCPConn(log) // Use new logger parameter name

	// Start TCP listener (for TTL=1 trick)
	listener, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, fmt.Errorf("faketcp: ListenTCP: %w", err)
	}
	conn.listener = listener
	if log != nil {
		log.Infof("faketcp: Control TCP listener started on %s", listener.Addr())
	}

	// Setup raw IP sockets on all available interfaces if laddr is unspecified,
	// or on the specified IP.
	interfaces, err := net.Interfaces()
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("faketcp: net.Interfaces: %w", err)
	}

	var createdHandles int
	for _, ifi := range interfaces {
		if (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagLoopback) != 0 {
			continue // Skip down or loopback interfaces
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			log.Warnf("faketcp: failed to get addrs for interface %s: %v", ifi.Name, err)
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			var handle *net.IPConn
			if laddr.IP != nil && !laddr.IP.IsUnspecified() && !laddr.IP.Equal(ip) {
				continue // If specific listen IP, only use that one
			}

			if ip.To4() != nil {
				handle, err = net.ListenIP("ip4:tcp", &net.IPAddr{IP: ip})
			} else if ip.To16() != nil {
				// Must ensure IPv6 is not link-local for general listening, or handle zones.
				// For now, assume global/ULA.
				handle, err = net.ListenIP("ip6:tcp", &net.IPAddr{IP: ip})
			} else {
				continue
			}

			if err != nil {
				log.Warnf("faketcp: ListenIP on %s (%s) failed: %v", ifi.Name, ip, err)
				continue
			}
			conn.handles = append(conn.handles, handle)
			go conn.captureFlow(handle, laddr.Port)
			createdHandles++
			if log != nil {
				log.Infof("faketcp: Raw IP listener started on %s (%s)", handle.LocalAddr(), ifi.Name)
			}
		}
	}

	if createdHandles == 0 {
		listener.Close()
		return nil, errors.New("faketcp: no suitable interfaces found to listen on for raw sockets")
	}

	// Setup iptables rules
	var rule []string
	if laddr.IP == nil || laddr.IP.IsUnspecified() || laddr.IP.To4() != nil { // Apply v4 if unspecified or v4
		ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			log.Warnf("faketcp: failed to init IPv4 iptables for listener: %v", err)
		} else {
			conn.v4iptables = ipt
			// Rule to drop packets from our listening port if TTL is 1
			// This targets outgoing packets from accepted control TCP conns.
			rule = []string{"-p", "tcp", "--sport", fmt.Sprint(laddr.Port),
				"-m", "ttl", "--ttl-eq", "1",
				"-j", "DROP"}
			if laddr.IP != nil && !laddr.IP.IsUnspecified() { // If specific IP, add to rule
				rule = append(rule, "-s", laddr.IP.String())
			}
			exists, err := ipt.Exists("filter", "OUTPUT", rule...)
			if err != nil {
				log.Warnf("faketcp: failed to check IPv4 listener iptables rule: %v", err)
			} else if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err != nil {
					log.Warnf("faketcp: failed to append IPv4 listener iptables rule: %v", err)
				} else {
					conn.v4iprule = rule
					log.Infof("faketcp: IPv4 listener iptables rule added: %v", rule)
				}
			}
		}
	}
	if laddr.IP == nil || laddr.IP.IsUnspecified() || laddr.IP.To16() != nil && laddr.IP.To4() == nil { // Apply v6 if unspecified or v6
		ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			log.Warnf("faketcp: failed to init IPv6 iptables for listener: %v", err)
		} else {
			conn.v6iptables = ipt
			rule = []string{"-p", "tcp", "--sport", fmt.Sprint(laddr.Port),
				"-m", "hl", "--hl-eq", "1",
				"-j", "DROP"}
			if laddr.IP != nil && !laddr.IP.IsUnspecified() {
				rule = append(rule, "-s", laddr.IP.String())
			}
			exists, err := ipt.Exists("filter", "OUTPUT", rule...)
			if err != nil {
				log.Warnf("faketcp: failed to check IPv6 listener iptables rule: %v", err)
			} else if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err != nil {
					log.Warnf("faketcp: failed to append IPv6 listener iptables rule: %v", err)
				} else {
					conn.v6iprule = rule
					log.Infof("faketcp: IPv6 listener iptables rule added: %v", rule)
				}
			}
		}
	}

	go conn.cleaner()
	go func() { // Accept loop for the control TCP listener
		for {
			tcpconn, err := listener.AcceptTCP()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) && log != nil {
					log.Errorf("faketcp: AcceptTCP error: %v", err)
				}
				return
			}
			if log != nil {
				log.Infof("faketcp: Accepted control TCP from %s", tcpconn.RemoteAddr())
			}

			if err := setTTL(tcpconn, 1); err != nil {
				log.Errorf("faketcp: setTTL(1) on accepted conn failed: %v", err)
				tcpconn.Close()
				continue
			}

			conn.lockflow(tcpconn.RemoteAddr(), func(flow *tcpFlow) {
				if flow.conn != nil { // Should not happen if cleaner is working
					log.Warnf("faketcp: existing flow.conn for %s, closing old one", tcpconn.RemoteAddr())
					flow.conn.Close()
				}
				flow.conn = tcpconn
				// Server learns client's ISN from SYN, sets its own ISN.
				// Here, we rely on captureFlow to see the SYN and set flow.ack.
				// Our flow.seq for server's first data packet can be random.
				var randBytes [4]byte
				rand.Read(randBytes[:])
				flow.seq = binary.BigEndian.Uint32(randBytes[:])
			})
			go func(acceptedConn *net.TCPConn) { // Discard data
				io.Copy(ioutil.Discard, acceptedConn)
				acceptedConn.Close()
				// Optionally, remove from flowTable if no raw packets received for a while
				// But cleaner() should handle this.
			}(tcpconn)
		}
	}()

	return conn, nil
}

// setTTL sets TTL on a TCP connection
func setTTL(c *net.TCPConn, ttl int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	addr := c.LocalAddr().(*net.TCPAddr) // Assuming TCPAddr for LocalAddr

	if addr.IP.To4() == nil { // IPv6
		opErr = raw.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		})
	} else { // IPv4
		opErr = raw.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})
	}
	return opErr
}

// setDSCPHandle sets DSCP on a raw IP connection handle
func setDSCPHandle(c *net.IPConn, dscp int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	// net.IPConn.LocalAddr() returns net.Addr, need to assert to *net.IPAddr
	addr, ok := c.LocalAddr().(*net.IPAddr)
	if !ok {
		return errors.New("faketcp: LocalAddr is not *net.IPAddr for DSCP setting")
	}

	if addr.IP.To4() == nil { // IPv6
		opErr = raw.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, dscp)
		})
	} else { // IPv4
		opErr = raw.Control(func(fd uintptr) {
			// DSCP is top 6 bits of TOS field
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, dscp<<2)
		})
	}
	return opErr
}
