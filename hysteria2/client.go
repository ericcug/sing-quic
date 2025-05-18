package hysteria2

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"
	"time"

	"fmt" // Added for logger adapter

	qtls "github.com/ericcug/sing-quic"
	congestion_meta1 "github.com/ericcug/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/ericcug/sing-quic/congestion_meta2"
	"github.com/ericcug/sing-quic/hysteria"
	hyCC "github.com/ericcug/sing-quic/hysteria/congestion"
	"github.com/ericcug/sing-quic/hysteria2/internal/protocol"
	"github.com/ericcug/sing-quic/pktconns/faketcp" // Added for faketcp
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
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
	Context            context.Context
	Dialer             N.Dialer
	Logger             logger.Logger
	BrutalDebug        bool
	ServerAddress      M.Socksaddr
	ServerPorts        []string
	HopInterval        time.Duration
	SendBPS            uint64
	ReceiveBPS         uint64
	SalamanderPassword string
	Password           string
	TLSConfig          aTLS.Config
	UDPDisabled        bool
	Transport          string // "udp" (default) or "faketcp"
}

type Client struct {
	ctx                context.Context
	dialer             N.Dialer
	logger             logger.Logger
	brutalDebug        bool
	serverAddr         M.Socksaddr
	serverPorts        []uint16
	hopInterval        time.Duration
	sendBPS            uint64
	receiveBPS         uint64
	salamanderPassword string
	password           string
	tlsConfig          aTLS.Config
	quicConfig         *quic.Config
	udpDisabled        bool
	transport          string // Added transport

	connAccess sync.RWMutex
	conn       *clientQUICConnection
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                !options.UDPDisabled,
		InitialStreamReceiveWindow:     hysteria.DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         hysteria.DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: hysteria.DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     hysteria.DefaultConnReceiveWindow,
		MaxIdleTimeout:                 hysteria.DefaultMaxIdleTimeout,
		KeepAlivePeriod:                hysteria.DefaultKeepAlivePeriod,
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	var serverPorts []uint16
	if len(options.ServerPorts) > 0 {
		var err error
		serverPorts, err = hysteria.ParsePorts(options.ServerPorts)
		if err != nil {
			return nil, err
		}
	}
	return &Client{
		ctx:                options.Context,
		dialer:             options.Dialer,
		logger:             options.Logger,
		brutalDebug:        options.BrutalDebug,
		serverAddr:         options.ServerAddress,
		serverPorts:        serverPorts,
		hopInterval:        options.HopInterval,
		sendBPS:            options.SendBPS,
		receiveBPS:         options.ReceiveBPS,
		salamanderPassword: options.SalamanderPassword,
		password:           options.Password,
		tlsConfig:          options.TLSConfig,
		quicConfig:         quicConfig,
		udpDisabled:        options.UDPDisabled,
		transport:          options.Transport, // Added transport
	}, nil
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
	dialLogic := func(targetAddr M.Socksaddr) (net.PacketConn, error) {
		var rawConn net.PacketConn
		var err error
		if c.transport == "faketcp" {
			ftLogger := &fakeTCPLoggerAdapter{Logger: c.logger}
			rawConn, err = faketcp.Dial("tcp", targetAddr.String(), ftLogger)
			if err != nil {
				return nil, E.Cause(err, "faketcp dial failed")
			}
		} else {
			// Default to UDP
			udpUnderlyingConn, dialErr := c.dialer.DialContext(c.ctx, "udp", targetAddr)
			if dialErr != nil {
				return nil, dialErr
			}
			rawConn = bufio.NewUnbindPacketConn(udpUnderlyingConn)
		}

		if c.salamanderPassword != "" {
			rawConn = NewSalamanderConn(rawConn, []byte(c.salamanderPassword))
		}
		return rawConn, nil
	}

	var (
		finalPacketConn net.PacketConn
		err             error
	)
	if len(c.serverPorts) == 0 {
		finalPacketConn, err = dialLogic(c.serverAddr)
	} else {
		hopDialFunc := func(hopTargetAddr M.Socksaddr) (net.PacketConn, error) {
			return dialLogic(hopTargetAddr)
		}
		finalPacketConn, err = hysteria.NewHopPacketConn(hopDialFunc, c.serverAddr, c.serverPorts, c.hopInterval)
	}
	if err != nil {
		return nil, err
	}

	var quicConn quic.EarlyConnection
	// Use finalPacketConn here
	http3Transport, err := qtls.CreateTransport(finalPacketConn, &quicConn, c.serverAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		finalPacketConn.Close() // Close the packetConn if transport creation fails
		return nil, err
	}
	request := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	protocol.AuthRequestToHeader(request.Header, protocol.AuthRequest{Auth: c.password, Rx: c.receiveBPS})
	response, err := http3Transport.RoundTrip(request.WithContext(ctx))
	if err != nil {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		finalPacketConn.Close() // Close the packetConn
		return nil, err
	}
	response.Body.Close()
	if response.StatusCode != protocol.StatusAuthOK {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		finalPacketConn.Close() // Close the packetConn
		return nil, E.New("authentication failed, status code: ", response.StatusCode)
	}
	authResponse := protocol.AuthResponseFromHeader(response.Header)
	actualTx := authResponse.Rx
	if actualTx == 0 || actualTx > c.sendBPS {
		actualTx = c.sendBPS
	}
	if !authResponse.RxAuto && actualTx > 0 {
		quicConn.SetCongestionControl(hyCC.NewBrutalSender(actualTx, c.brutalDebug, c.logger))
	} else {
		timeFunc := ntp.TimeFuncFromContext(c.ctx)
		if timeFunc == nil {
			timeFunc = time.Now
		}
		quicConn.SetCongestionControl(congestion_meta2.NewBbrSender(
			congestion_meta2.DefaultClock{TimeFunc: timeFunc},
			congestion.ByteCount(quicConn.Config().InitialPacketSize),
			congestion.ByteCount(congestion_meta1.InitialCongestionWindow),
		))
	}
	conn := &clientQUICConnection{
		quicConn:    quicConn,
		rawConn:     finalPacketConn, // Use finalPacketConn
		connDone:    make(chan struct{}),
		udpDisabled: !authResponse.UDPEnabled,
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

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
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
	var sessionID uint32
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, func() {
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, sessionID)
		conn.udpAccess.Unlock()
	})
	conn.udpAccess.Lock()
	sessionID = conn.udpSessionID
	conn.udpSessionID++
	conn.udpConnMap[sessionID] = clientPacketConn
	conn.udpAccess.Unlock()
	clientPacketConn.sessionID = sessionID
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
	quicConn     quic.Connection
	rawConn      io.Closer
	closeOnce    sync.Once
	connDone     chan struct{}
	connErr      error
	udpDisabled  bool
	udpAccess    sync.RWMutex
	udpConnMap   map[uint32]*udpPacketConn
	udpSessionID uint32
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
	status, errorMessage, err := protocol.ReadTCPResponse(c.Stream)
	if err != nil {
		return 0, baderror.WrapQUIC(err)
	}
	if !status {
		err = E.New("remote error: ", errorMessage)
		return
	}
	c.responseRead = true
	n, err = c.Stream.Read(p)
	return n, baderror.WrapQUIC(err)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if !c.requestWritten {
		buffer := protocol.WriteTCPRequest(c.destination.String(), p)
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
