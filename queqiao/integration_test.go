package queqiao_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/queqiao"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func generateSelfSignedCertificate() (tls.Certificate, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		IsCA:                  true,
		BasicConstraintsValid: true,
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool.AddCert(parsed)
	return cert, pool, nil
}

func setupEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }
}

func setupUDPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:n], addr)
		}
	}()
	return conn.LocalAddr().String(), func() { _ = conn.Close() }
}

// directHandler opens what the client asked for. A TCP flow is dialed; a
// packet connection is a raw UDP relay that names its peer per packet.
type directHandler struct{}

func (directHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		remote, err := net.Dial("tcp", destination.String())
		if err != nil {
			return
		}
		defer remote.Close()
		go func() {
			_, _ = io.Copy(remote, conn)
			if closeWriter, ok := remote.(interface{ CloseWrite() error }); ok {
				_ = closeWriter.CloseWrite()
			}
		}()
		_, _ = io.Copy(conn, remote)
	}()
}

func (directHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		remote, err := net.ListenUDP("udp", nil)
		if err != nil {
			return
		}
		defer remote.Close()
		go func() {
			buffer := make([]byte, 65535)
			for {
				n, addr, err := remote.ReadFromUDP(buffer)
				if err != nil {
					return
				}
				packetBuffer := buf.As(buffer[:n])
				if conn.WritePacket(packetBuffer, M.SocksaddrFromNet(addr).Unwrap()) != nil {
					packetBuffer.Release()
					return
				}
			}
		}()
		buffer := buf.New()
		defer buffer.Release()
		for {
			buffer.Reset()
			packetDestination, err := conn.ReadPacket(buffer)
			if err != nil {
				return
			}
			address := packetDestination.Addr
			port := packetDestination.Port
			if packetDestination.IsDomain() {
				addresses, resolveErr := net.DefaultResolver.LookupIPAddr(ctx, packetDestination.Fqdn)
				if resolveErr != nil || len(addresses) == 0 {
					continue
				}
				address, _ = netip.AddrFromSlice(addresses[0].IP)
			}
			_, _ = remote.WriteToUDP(buffer.Bytes(), net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, port)))
		}
	}()
}

func startTestServer(t *testing.T, handler queqiao.ServiceHandler) string {
	t.Helper()
	serverCert, pool, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatal(err)
	}
	testCertificatePool = pool
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service, err := queqiao.NewService(queqiao.ServiceOptions{
		Context:   ctx,
		Users:     []string{"secret123"},
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{serverCert}},
		Handler:   handler,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = service.Start(packetConn)
	}()
	return packetConn.LocalAddr().String()
}
