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
	"log/slog"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/queqiao"
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
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

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

	stop := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return listener.Addr().String(), func() {
		close(stop)
		_ = listener.Close()
	}
}

func setupUDPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()

	return pc.LocalAddr().String(), func() {
		_ = pc.Close()
	}
}

func TestTCPDataTransfer(t *testing.T) {
	echoAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()

	serverCert, pool, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatal(err)
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"queqiao-transport/1"},
	}

	clientTLS := &tls.Config{
		RootCAs:            pool,
		ServerName:         "127.0.0.1",
		NextProtos:         []string{"queqiao-transport/1"},
		InsecureSkipVerify: true,
	}

	service, err := queqiao.NewService(queqiao.ServiceOptions{
		Users:     []string{"secret123"},
		TLSConfig: serverTLS,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := packetConn.LocalAddr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = service.ServePacketConn(ctx, packetConn)
	}()

	client, err := queqiao.NewClient(queqiao.ClientOptions{
		RemoteAddr:       serverAddr,
		Password:         "secret123",
		TLSConfig:        clientTLS,
		DialTimeout:      2 * time.Second,
		HandshakeTimeout: 2 * time.Second,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Dial TCP through tunnel
	conn, err := client.DialConn(ctx, echoAddr)
	if err != nil {
		t.Fatalf("dial connection: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("Hello, Queqiao over sing-quic!")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	if string(reply) != string(payload) {
		t.Fatalf("reply = %q, want %q", string(reply), string(payload))
	}
}

func TestUDPDataTransfer(t *testing.T) {
	echoAddr, stopEcho := setupUDPEchoServer(t)
	defer stopEcho()

	serverCert, pool, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatal(err)
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"queqiao-transport/1"},
	}

	clientTLS := &tls.Config{
		RootCAs:            pool,
		ServerName:         "127.0.0.1",
		NextProtos:         []string{"queqiao-transport/1"},
		InsecureSkipVerify: true,
	}

	service, err := queqiao.NewService(queqiao.ServiceOptions{
		Users:     []string{"secret123"},
		TLSConfig: serverTLS,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := packetConn.LocalAddr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = service.ServePacketConn(ctx, packetConn)
	}()

	client, err := queqiao.NewClient(queqiao.ClientOptions{
		RemoteAddr:       serverAddr,
		Password:         "secret123",
		TLSConfig:        clientTLS,
		DialTimeout:      2 * time.Second,
		HandshakeTimeout: 2 * time.Second,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	pc, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	defer pc.Close()

	udpEchoAddr, err := net.ResolveUDPAddr("udp", echoAddr)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("Hello UDP over Queqiao!")
	if _, err := pc.WriteTo(payload, udpEchoAddr); err != nil {
		t.Fatalf("write to: %v", err)
	}

	buf := make([]byte, 1024)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read from: %v", err)
	}

	if string(buf[:n]) != string(payload) {
		t.Fatalf("got %q, want %q", string(buf[:n]), string(payload))
	}
	if from.String() != echoAddr {
		t.Logf("got from addr: %s, expected: %s", from.String(), echoAddr)
	}
}

func TestAuthenticationFailure(t *testing.T) {
	serverCert, pool, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatal(err)
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"queqiao-transport/1"},
	}

	clientTLS := &tls.Config{
		RootCAs:            pool,
		ServerName:         "127.0.0.1",
		NextProtos:         []string{"queqiao-transport/1"},
		InsecureSkipVerify: true,
	}

	service, err := queqiao.NewService(queqiao.ServiceOptions{
		Users:     []string{"correct-password"},
		TLSConfig: serverTLS,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := packetConn.LocalAddr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		_ = service.ServePacketConn(ctx, packetConn)
	}()

	client, err := queqiao.NewClient(queqiao.ClientOptions{
		RemoteAddr:       serverAddr,
		Password:         "wrong-password",
		TLSConfig:        clientTLS,
		DialTimeout:      time.Second,
		HandshakeTimeout: time.Second,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Dialing connection should fail due to bad password
	conn, err := client.DialConn(ctx, "127.0.0.1:80")
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial succeeded with wrong password")
	}
}
