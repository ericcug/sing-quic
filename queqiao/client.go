package queqiao

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"os"
	"syscall"

	"github.com/sagernet/sing-quic/queqiao/internal/pep"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ClientOptions configures a queqiao client. Transport tuning lives in the
// queqiao core and follows its own defaults; only the deployment surface is
// exposed here.
type ClientOptions struct {
	// Context owns the client's lifetime. Cancelling it stops the uplink
	// watcher and abandons every pooled connection.
	Context    context.Context
	Logger     logger.Logger
	Dialer     N.Dialer
	RemoteAddr string
	Password   string
	TLSConfig  *tls.Config
	// SocketControl is applied to every outer socket before it is bound, which
	// is what keeps a mobile client's traffic out of its own tunnel.
	SocketControl func(network, address string, conn syscall.RawConn) error
	// HopPortCount enables reactive UDP port hopping. 0 and 1 disable it.
	HopPortCount int
}

type Client struct {
	core   *pep.Client
	logger logger.Logger
}

// NewClient builds a client. The QUIC pool it maintains is shared by every
// flow this client opens; the first handshake happens on the first flow.
func NewClient(options ClientOptions) (*Client, error) {
	if options.Context == nil {
		options.Context = context.Background()
	}
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	if options.TLSConfig == nil {
		return nil, E.New("queqiao: TLS configuration is required")
	}
	tlsConfig := options.TLSConfig
	tlsConfig = tlsConfig.Clone()
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{pep.ALPN}
	}
	core, err := pep.NewClient(pep.ClientConfig{
		RemoteAddr:     options.RemoteAddr,
		Dialer:         options.Dialer,
		Password:       options.Password,
		TLSConfig:      tlsConfig,
		SocketControl:  options.SocketControl,
		HopPortCount:   options.HopPortCount,
		EnableQUICPool: true,
		Logger:         slog.New(&slogHandler{logger: options.Logger}),
	})
	if err != nil {
		return nil, err
	}
	return &Client{
		core:   core,
		logger: options.Logger,
	}, nil
}

// Start begins the background path measurement and uplink watch. It is
// separate from construction so a host can choose when its network stack is
// ready; calling it more than once is harmless.
func (c *Client) Start(ctx context.Context) {
	c.core.Start(ctx)
}

// DialConn opens one flow to destination. onClose receives the flow's
// terminal error exactly once, as the sing connection handlers expect.
func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr, onClose N.CloseHandlerFunc) (net.Conn, error) {
	return c.core.DialConn(ctx, destination.String(), onClose)
}

// ListenPacket opens a UDP association. The returned connection can be used
// both as a net.PacketConn and as a sing N.PacketConn.
func (c *Client) ListenPacket(ctx context.Context, onClose N.CloseHandlerFunc) (*UDPConn, error) {
	packetConn, err := c.core.ListenPacket(ctx, onClose)
	if err != nil {
		return nil, err
	}
	return newUDPPacketConn(packetConn), nil
}

// CloseIdleConnections retires the pooled connection when no flow uses it,
// which is what a host reports after the network path changed.
func (c *Client) CloseIdleConnections() {
	c.core.CloseIdleConnections()
}

func (c *Client) CloseWithError(err error) error {
	c.core.CloseWithError(err)
	return nil
}

func (c *Client) Close() error {
	return c.CloseWithError(os.ErrClosed)
}
