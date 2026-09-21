package queqiao

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/sagernet/sing-quic/queqiao/internal/pep"
)

type DestinationDialer = pep.DestinationDialer

type ServiceOptions struct {
	ListenAddr        string
	Authenticator     func(auth string) (user string, ok bool)
	Users             []string // fallback if Authenticator is nil
	TLSConfig         *tls.Config
	Logger            *slog.Logger
	MaxSessions       int
	HandshakeTimeout  time.Duration
	IdleTimeout       time.Duration
	MaxLifetime       time.Duration
	HopPortCount      int
	UDPOnStream       bool
	DestinationDialer DestinationDialer
}

type Service struct {
	pepServer *pep.Server
	cancel    context.CancelFunc
}

func NewService(opts ServiceOptions) (*Service, error) {
	if opts.TLSConfig == nil {
		return nil, errors.New("queqiao: TLSConfig is required for service")
	}
	if opts.Authenticator == nil && len(opts.Users) == 0 {
		return nil, errors.New("queqiao: at least one user password or Authenticator is required")
	}

	pepCfg := pep.ServerConfig{
		ListenAddr:        opts.ListenAddr,
		Authenticator:     opts.Authenticator,
		Passwords:         opts.Users,
		TLSConfig:         opts.TLSConfig,
		Logger:            opts.Logger,
		MaxSessions:       opts.MaxSessions,
		HandshakeTimeout:  opts.HandshakeTimeout,
		FlowIdleTimeout:   opts.IdleTimeout,
		FlowMaxLifetime:   opts.MaxLifetime,
		HopPortCount:      opts.HopPortCount,
		UDPOnStream:       opts.UDPOnStream,
		DestinationPolicy: opts.DestinationDialer,
	}

	s, err := pep.NewServer(pepCfg)
	if err != nil {
		return nil, err
	}

	return &Service{pepServer: s}, nil
}

func (s *Service) Serve(ctx context.Context) error {
	serveCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	return s.pepServer.Serve(serveCtx)
}

func (s *Service) ServePacketConn(ctx context.Context, conn net.PacketConn) error {
	serveCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	return s.pepServer.ServePacketConn(serveCtx, conn)
}

func (s *Service) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.pepServer != nil {
		return s.pepServer.Close()
	}
	return nil
}

// UserFromContext returns the authenticated username from the context.
func UserFromContext(ctx context.Context) string {
	return pep.UserFromContext(ctx)
}
