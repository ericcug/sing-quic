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
	Users             []string
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
	if len(opts.Users) == 0 {
		return nil, errors.New("queqiao: at least one user password is required")
	}

	pepCfg := pep.ServerConfig{
		ListenAddr:        opts.ListenAddr,
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
