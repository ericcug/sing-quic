package queqiao

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"sync"

	"github.com/sagernet/sing-quic/queqiao/internal/pep"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ServiceHandler receives the connections queqiao opens on the gateway's
// behalf, once they are authenticated.
type ServiceHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

// ServiceOptions configures a queqiao gateway. Transport tuning lives in the
// queqiao core and follows its own defaults; only the deployment surface is
// exposed here.
type ServiceOptions struct {
	Context       context.Context
	Logger        logger.Logger
	Users         []string
	Authenticator func(auth string) (user string, ok bool)
	TLSConfig     *tls.Config
	HopPortCount  int
	Handler       ServiceHandler
}

type Service struct {
	core      *pep.Server
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	logger    logger.Logger
	handler   ServiceHandler
}

func NewService(options ServiceOptions) (*Service, error) {
	if options.Context == nil {
		options.Context = context.Background()
	}
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	if options.TLSConfig == nil {
		return nil, E.New("queqiao: TLS configuration is required")
	}
	tlsConfig := options.TLSConfig.Clone()
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{pep.ALPN}
	}
	serviceCtx, cancel := context.WithCancel(options.Context)
	service := &Service{
		ctx:     serviceCtx,
		cancel:  cancel,
		logger:  options.Logger,
		handler: options.Handler,
	}
	core, err := pep.NewServer(pep.ServerConfig{
		TLSConfig:         tlsConfig,
		Authenticator:     options.Authenticator,
		Passwords:         options.Users,
		HopPortCount:      options.HopPortCount,
		DestinationPolicy: service,
		Logger:            slog.New(&slogHandler{logger: options.Logger}),
	})
	if err != nil {
		cancel()
		return nil, err
	}
	service.core = core
	return service, nil
}

// Start runs the gateway on an already-bound socket until ctx is cancelled.
func (s *Service) Start(packetConn net.PacketConn) error {
	return s.core.ServePacketConn(s.ctx, packetConn)
}

// Close stops accepting connections, tears down the flows in flight and
// releases the listener's serve loop.
func (s *Service) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
	})
	return s.core.Close()
}

func (s *Service) DialContext(ctx context.Context, user string, destination string) (net.Conn, error) {
	input, output := pep.NewStreamPipe()
	var source M.Socksaddr
	if remote := s.remoteAddr(ctx); remote != nil {
		source = M.SocksaddrFromNet(remote).Unwrap()
	}
	go s.handler.NewConnectionEx(
		auth.ContextWithUser(ctx, user),
		output,
		source,
		M.ParseSocksaddr(destination).Unwrap(),
		N.OnceClose(func(it error) {
			input.Close()
		}),
	)
	return input, nil
}

func (s *Service) ListenPacket(ctx context.Context, user string) (N.PacketConn, error) {
	left, right := newPacketPipe()
	var source M.Socksaddr
	if remote := s.remoteAddr(ctx); remote != nil {
		source = M.SocksaddrFromNet(remote).Unwrap()
	}
	go s.handler.NewPacketConnectionEx(
		auth.ContextWithUser(ctx, user),
		right,
		source,
		M.Socksaddr{},
		N.OnceClose(func(it error) {
			_ = left.Close()
		}),
	)
	return left, nil
}

// remoteAddr is the client's address on the authenticated connection the
// flow arrived on, which is what a source rule matches against. It is read
// from the per-flow context, so it names the connection this flow uses rather
// than the gateway's listening socket.
func (s *Service) remoteAddr(ctx context.Context) net.Addr {
	return pep.PeerAddr(ctx)
}

// ALPN is the application protocol every queqiao peer negotiates.
const ALPN = pep.ALPN

var _ pep.DestinationDialer = (*Service)(nil)
