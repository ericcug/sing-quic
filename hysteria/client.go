package hysteria

import (
	"context"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"fmt" // Added for logger adapter

	qtls "github.com/ericcug/sing-quic"
	hyCC "github.com/ericcug/sing-quic/hysteria/congestion"
	"github.com/ericcug/sing-quic/pktconns/faketcp"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

// fakeTCPLoggerAdapter adapts sing/common/logger.Logger to faketcp.logger
type fakeTCPLoggerAdapter struct {
	logger.Logger
}

func (a *fakeTCPLoggerAdapter) Debugf(format string, args ...interface{}) {
	a.Logger.Debug(fmt.Sprintf(format, args...))
}

func (a *fakeTCPLoggerAdapter) Infof(format string, args ...interface{}) {
	a.Logger.Info(fmt.Sprintf(format, args...))
}

func (a *fakeTCPLoggerAdapter) Warnf(format string, args ...interface{}) {
	a.Logger.Warn(fmt.Sprintf(format, args...))
}

func (a *fakeTCPLoggerAdapter) Errorf(format string, args ...interface{}) {
	a.Logger.Error(fmt.Sprintf(format, args...))
}

type ClientOptions struct {
	Context       context.Context
	Dialer        N.Dialer
	Logger        logger.Logger
	BrutalDebug   bool
	ServerAddress M.Socksaddr
	ServerPorts   []string
	HopInterval   time.Duration
	SendBPS       uint64
	ReceiveBPS    uint64
	XPlusPassword string
	Password      string
	TLSConfig     aTLS.Config
	UDPDisabled   bool
	Transport     string // "udp" (default) or "faketcp"

	// Legacy options

	ConnReceiveWindow   uint64
	StreamReceiveWindow uint64
	DisableMTUDiscovery bool
}

type Client struct {
	ctx           context.Context
	dialer        N.Dialer
	logger        logger.Logger
	brutalDebug   bool
	serverAddr    M.Socksaddr
	serverPorts   []uint16
	hopInterval   time.Duration
	sendBPS       uint64
	receiveBPS    uint64
	xplusPassword string
	password      string
	tlsConfig     aTLS.Config
	quicConfig    *quic.Config
	udpDisabled   bool
	transport     string

	connAccess sync.RWMutex
	conn       *clientQUICConnection
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     DefaultConnReceiveWindow,
		MaxIdleTimeout:                 DefaultMaxIdleTimeout,
		KeepAlivePeriod:                DefaultKeepAlivePeriod,
	}
	if options.StreamReceiveWindow != 0 {
		quicConfig.InitialStreamReceiveWindow = options.StreamReceiveWindow
		quicConfig.MaxStreamReceiveWindow = options.StreamReceiveWindow
	}
	if options.ConnReceiveWindow != 0 {
		quicConfig.InitialConnectionReceiveWindow = options.ConnReceiveWindow
		quicConfig.MaxConnectionReceiveWindow = options.ConnReceiveWindow
	}
	if options.DisableMTUDiscovery {
		quicConfig.DisablePathMTUDiscovery = true
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{DefaultALPN})
	}
	if options.SendBPS == 0 {
		return nil, E.New("missing upload speed")
	} else if options.SendBPS < MinSpeedBPS {
		return nil, E.New("invalid upload speed")
	}
	if options.ReceiveBPS == 0 {
		return nil, E.New("missing download speed")
	} else if options.ReceiveBPS < MinSpeedBPS {
		return nil, E.New("invalid download speed")
	}
	var serverPorts []uint16
	if len(options.ServerPorts) > 0 {
		var err error
		serverPorts, err = ParsePorts(options.ServerPorts)
		if err != nil {
			return nil, err
		}
	}
	return &Client{
		ctx:           options.Context,
		dialer:        options.Dialer,
		logger:        options.Logger,
		brutalDebug:   options.BrutalDebug,
		serverAddr:    options.ServerAddress,
		serverPorts:   serverPorts,
		hopInterval:   options.HopInterval,
		sendBPS:       options.SendBPS,
		receiveBPS:    options.ReceiveBPS,
		xplusPassword: options.XPlusPassword,
		password:      options.Password,
		tlsConfig:     options.TLSConfig,
		quicConfig:    quicConfig,
		udpDisabled:   options.UDPDisabled,
		transport:     options.Transport,
	}, nil
}

func ParsePorts(serverPorts []string) ([]uint16, error) {
	var portList []uint16
	for _, portRange := range serverPorts {
		if !strings.Contains(portRange, ":") {
			return nil, E.New("bad port range: ", portRange)
		}
		subIndex := strings.Index(portRange, ":")
		var (
			start, end uint64
			err        error
		)
		if subIndex > 0 {
			start, err = strconv.ParseUint(portRange[:subIndex], 10, 16)
			if err != nil {
				return nil, E.Cause(err, E.Cause(err, "bad port range: ", portRange))
			}
		}
		if subIndex == len(portRange)-1 {
			end = math.MaxUint16
		} else {
			end, err = strconv.ParseUint(portRange[subIndex+1:], 10, 16)
			if err != nil {
				return nil, E.Cause(err, E.Cause(err, "bad port range: ", portRange))
			}
		}
		for i := start; i <= end; i++ {
			portList = append(portList, uint16(i))
		}
	}
	return portList, nil
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	conn := c.conn
	if conn != nil && conn.active() {
		return conn, nil
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	conn = c.conn
	if conn != nil && conn.active() {
		return conn, nil
	}
	conn, err := c.offerNew(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	var (
		packetConn net.PacketConn
		err        error
	)

	dialLogic := func(targetAddr M.Socksaddr) (net.PacketConn, error) {
		var rawConn net.PacketConn
		if c.transport == "faketcp" {
			ftLogger := &fakeTCPLoggerAdapter{Logger: c.logger}
			fakeTCPRawConn, dialErr := faketcp.Dial("tcp", targetAddr.String(), ftLogger)
			if dialErr != nil {
				return nil, E.Cause(dialErr, "faketcp dial failed")
			}
			rawConn = fakeTCPRawConn
		} else {
			// Default to UDP
			udpUnderlyingConn, dialErr := c.dialer.DialContext(c.ctx, "udp", targetAddr)
			if dialErr != nil {
				return nil, dialErr
			}
			rawConn = bufio.NewUnbindPacketConn(udpUnderlyingConn)
		}

		if c.xplusPassword != "" {
			rawConn = NewXPlusPacketConn(rawConn, []byte(c.xplusPassword))
		}
		return rawConn, nil
	}

	if len(c.serverPorts) == 0 {
		packetConn, err = dialLogic(c.serverAddr)
	} else {
		// NewHopPacketConn expects a function that dials a specific address.
		// The dialLogic function already does this.
		hopDialFunc := func(hopTargetAddr M.Socksaddr) (net.PacketConn, error) {
			return dialLogic(hopTargetAddr)
		}
		packetConn, err = NewHopPacketConn(hopDialFunc, c.serverAddr, c.serverPorts, c.hopInterval)
	}

	if err != nil {
		return nil, err
	}
	quicConn, err := qtls.Dial(c.ctx, packetConn, c.serverAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	controlStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	err = WriteClientHello(controlStream, ClientHello{
		SendBPS: c.sendBPS,
		RecvBPS: c.receiveBPS,
		Auth:    c.password,
	})
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	serverHello, err := ReadServerHello(controlStream)
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	if !serverHello.OK {
		packetConn.Close()
		return nil, E.New("remote error: ", serverHello.Message)
	}
	quicConn.SetCongestionControl(hyCC.NewBrutalSender(uint64(math.Min(float64(serverHello.RecvBPS), float64(c.sendBPS))), c.brutalDebug, c.logger))
	conn := &clientQUICConnection{
		quicConn:    quicConn,
		rawConn:     packetConn,
		connDone:    make(chan struct{}),
		udpDisabled: !quicConn.ConnectionState().SupportsDatagrams,
		udpConnMap:  make(map[uint32]*udpPacketConn),
	}
	if !c.udpDisabled {
		go c.loopMessages(conn)
	}
	c.conn = conn
	return conn, nil
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		destination: destination,
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if c.udpDisabled {
		return nil, os.ErrInvalid
	}
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	if conn.udpDisabled {
		return nil, E.New("UDP disabled by server")
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	buffer := WriteClientRequest(ClientRequest{
		UDP:  true,
		Host: destination.AddrString(),
		Port: destination.Port,
	}, nil)
	_, err = stream.Write(buffer.Bytes())
	buffer.Release()
	if err != nil {
		stream.Close()
		return nil, err
	}
	response, err := ReadServerResponse(stream)
	if err != nil {
		stream.Close()
		return nil, err
	}
	if !response.OK {
		stream.Close()
		return nil, E.New("remote error: ", response.Message)
	}
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, func() {
		stream.CancelRead(0)
		stream.Close()
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, response.UDPSessionID)
		conn.udpAccess.Unlock()
	})
	conn.udpAccess.Lock()
	if debug.Enabled {
		if _, connExists := conn.udpConnMap[response.UDPSessionID]; connExists {
			stream.Close()
			return nil, E.New("udp session id duplicated")
		}
	}
	conn.udpConnMap[response.UDPSessionID] = clientPacketConn
	conn.udpAccess.Unlock()
	clientPacketConn.sessionID = response.UDPSessionID
	go func() {
		holdBuffer := make([]byte, 1024)
		for {
			_, hErr := stream.Read(holdBuffer)
			if hErr != nil {
				break
			}
		}
		clientPacketConn.closeWithError(E.Cause(net.ErrClosed, "hold stream closed"))
	}()
	return clientPacketConn, nil
}

func (c *Client) CloseWithError(err error) error {
	conn := c.conn
	if conn != nil {
		conn.closeWithError(err)
	}
	return nil
}

type clientQUICConnection struct {
	quicConn    quic.Connection
	rawConn     io.Closer
	closeOnce   sync.Once
	connDone    chan struct{}
	connErr     error
	udpDisabled bool
	udpAccess   sync.RWMutex
	udpConnMap  map[uint32]*udpPacketConn
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		close(c.connDone)
		_ = c.quicConn.CloseWithError(0, "")
		_ = c.rawConn.Close()
	})
}

type clientConn struct {
	quic.Stream
	destination    M.Socksaddr
	requestWritten bool
	responseRead   bool
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.responseRead {
		n, err = c.Stream.Read(p)
		return n, baderror.WrapQUIC(err)
	}
	response, err := ReadServerResponse(c.Stream)
	if err != nil {
		return 0, baderror.WrapQUIC(err)
	}
	if !response.OK {
		err = E.New("remote error: ", response.Message)
		return
	}
	c.responseRead = true
	n, err = c.Stream.Read(p)
	return n, baderror.WrapQUIC(err)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if !c.requestWritten {
		buffer := WriteClientRequest(ClientRequest{
			UDP:  false,
			Host: c.destination.AddrString(),
			Port: c.destination.Port,
		}, p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return
		}
		c.requestWritten = true
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, baderror.WrapQUIC(err)
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
