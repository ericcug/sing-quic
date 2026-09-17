package queqiao

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/sagernet/sing-quic/queqiao/internal/pep"
)

type ClientOptions struct {
	RemoteAddr          string
	LocalAddress        string
	Password            string
	TLSConfig           *tls.Config
	DialTimeout         time.Duration
	HandshakeTimeout    time.Duration
	IdleTimeout         time.Duration
	MaxLifetime         time.Duration
	SocketControl       func(network, address string, c syscall.RawConn) error
	Logger              *slog.Logger
	Congestion          string
	BrutalBytesPerSec   uint64
	AdaptiveMinBytesSec uint64
	AdaptiveMaxBytesSec uint64
	HopPortCount        int
	UDPOnStream         bool
}

type Client struct {
	pepClient *pep.Client
}

func NewClient(opts ClientOptions) (*Client, error) {
	if opts.RemoteAddr == "" {
		return nil, errors.New("queqiao: remote address is required")
	}
	if opts.Password == "" {
		return nil, errors.New("queqiao: password is required")
	}
	if opts.TLSConfig == nil {
		opts.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	pepCfg := pep.ClientConfig{
		RemoteAddr:          opts.RemoteAddr,
		LocalAddress:        opts.LocalAddress,
		Password:            opts.Password,
		TLSConfig:           opts.TLSConfig,
		DialTimeout:         opts.DialTimeout,
		HandshakeTimeout:    opts.HandshakeTimeout,
		FlowIdleTimeout:     opts.IdleTimeout,
		FlowMaxLifetime:     opts.MaxLifetime,
		SocketControl:       opts.SocketControl,
		Logger:              opts.Logger,
		Congestion:          pep.CongestionControlKind(opts.Congestion),
		BrutalBytesPerSec:   opts.BrutalBytesPerSec,
		AdaptiveMinBytesSec: opts.AdaptiveMinBytesSec,
		AdaptiveMaxBytesSec: opts.AdaptiveMaxBytesSec,
		HopPortCount:        opts.HopPortCount,
		UDPOnStream:         opts.UDPOnStream,
	}

	c, err := pep.NewClient(pepCfg)
	if err != nil {
		return nil, err
	}

	c.Start(context.Background())
	return &Client{pepClient: c}, nil
}

func (c *Client) DialConn(ctx context.Context, destination string) (net.Conn, error) {
	return c.pepClient.DialConn(ctx, destination)
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return c.pepClient.ListenPacket(ctx)
}

func (c *Client) Close() error {
	if c.pepClient != nil {
		c.pepClient.Close()
	}
	return nil
}
