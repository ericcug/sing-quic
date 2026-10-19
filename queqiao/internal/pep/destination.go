package pep

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/sagernet/sing-quic/queqiao/internal/session"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// directDestinationPolicy is the standalone gateway's own dialer. An embedding
// host supplies its own so flows follow its routing.
type directDestinationPolicy struct {
	policy DestinationPolicy
}

func (p *directDestinationPolicy) DialContext(ctx context.Context, _ string, destination string) (net.Conn, error) {
	return p.policy.DialContext(ctx, destination)
}

func (p *directDestinationPolicy) ListenPacket(ctx context.Context, _ string) (N.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &directPacketConn{conn: conn, policy: p.policy}, nil
}

type directPacketConn struct {
	conn   *net.UDPConn
	policy DestinationPolicy
}

func (c *directPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	for {
		n, addr, err := c.conn.ReadFromUDP(buffer.FreeBytes())
		if err != nil {
			return M.Socksaddr{}, err
		}
		destination, err := session.DestinationFromUDPAddr(addr)
		if err != nil {
			continue
		}
		buffer.Truncate(int(n))
		return M.ParseSocksaddr(destination), nil
	}
}

func (c *directPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	addresses, err := c.policy.ResolveUDPAddr(context.Background(), destination.String())
	if err != nil {
		return err
	}
	for _, address := range addresses {
		_, err = c.conn.WriteToUDP(buffer.Bytes(), address)
		if err == nil {
			return nil
		}
	}
	return err
}

func (c *directPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return c.conn.ReadFrom(p)
}

func (c *directPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.conn.WriteTo(p, addr)
}

func (c *directPacketConn) Close() error                       { return c.conn.Close() }
func (c *directPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *directPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *directPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *directPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// DestinationDialer opens the application connections a flow carries. The
// authenticated user is passed so an embedding router can attribute the flow.
// A packet connection is one association: packets name their own destination.
type DestinationDialer interface {
	DialContext(ctx context.Context, user string, destination string) (net.Conn, error)
	ListenPacket(ctx context.Context, user string) (N.PacketConn, error)
}

type DestinationPolicy struct {
	AllowPrivate bool
	DialTimeout  time.Duration
}

var additionallyForbidden = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// IPv4-translation prefixes can encode a private IPv4 destination in an
	// address that netip classifies as global IPv6. Reject them at this layer
	// instead of relying on every NAT64 or 6to4 relay to enforce RFC filtering.
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	// Current IANA non-global special-purpose ranges that otherwise satisfy
	// IsGlobalUnicast. Loopback, ULA, link-local, and multicast are handled by
	// the standard netip predicates below.
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
}

func (p DestinationPolicy) DialContext(ctx context.Context, destination string) (net.Conn, error) {
	host, port, err := parseDestination(destination)
	if err != nil {
		return nil, err
	}
	timeout := p.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var addresses []net.IPAddr
	if parsed := net.ParseIP(host); parsed != nil {
		addresses = []net.IPAddr{{IP: parsed}}
	} else {
		addresses, err = net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, errors.New("destination resolution failed")
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("destination did not resolve")
	}

	dialer := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, candidate := range addresses {
		if !p.AllowPrivate && !publicDestinationIP(candidate.IP) {
			lastErr = errors.New("destination address is not public")
			continue
		}
		address := net.JoinHostPort(candidate.IP.String(), strconv.Itoa(port))
		conn, dialErr := dialer.DialContext(ctx, "tcp", address)
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("destination unavailable")
	}
	return nil, fmt.Errorf("destination unavailable: %w", lastErr)
}

// ResolveUDPAddr validates and resolves a destination using the same
// public-address policy as TCP, returning concrete addresses only.
func (p DestinationPolicy) ResolveUDPAddr(ctx context.Context, destination string) ([]*net.UDPAddr, error) {
	host, port, err := parseDestination(destination)
	if err != nil {
		return nil, err
	}
	timeout := p.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var addresses []net.IPAddr
	if parsed := net.ParseIP(host); parsed != nil {
		addresses = []net.IPAddr{{IP: parsed}}
	} else {
		addresses, err = net.DefaultResolver.LookupIPAddr(resolveCtx, host)
		if err != nil {
			return nil, errors.New("destination resolution failed")
		}
	}
	result := make([]*net.UDPAddr, 0, len(addresses))
	for _, candidate := range addresses {
		if !p.AllowPrivate && !publicDestinationIP(candidate.IP) {
			continue
		}
		result = append(result, &net.UDPAddr{IP: append(net.IP(nil), candidate.IP...), Port: port})
	}
	if len(result) == 0 {
		return nil, errors.New("destination address is not public or did not resolve")
	}
	return result, nil
}

func parseDestination(destination string) (string, int, error) {
	host, portText, err := net.SplitHostPort(destination)
	if err != nil || host == "" {
		return "", 0, errors.New("invalid destination")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("invalid destination port")
	}
	return host, port, nil
}

func publicDestinationIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, prefix := range additionallyForbidden {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

type peerAddrKey struct{}

// WithPeerAddr records the authenticated connection's peer address for the
// flows it carries, so a host can attribute them to a client.
func WithPeerAddr(ctx context.Context, addr net.Addr) context.Context {
	if addr == nil {
		return ctx
	}
	return context.WithValue(ctx, peerAddrKey{}, addr)
}

// PeerAddr returns the address recorded by WithPeerAddr.
func PeerAddr(ctx context.Context) net.Addr {
	addr, _ := ctx.Value(peerAddrKey{}).(net.Addr)
	return addr
}
