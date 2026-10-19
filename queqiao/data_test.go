package queqiao_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/queqiao"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

var testCertificatePool *x509.CertPool

func newTestClient(t *testing.T, serverAddr string) *queqiao.Client {
	t.Helper()
	if testCertificatePool == nil {
		t.Fatal("test certificate pool is not initialized")
	}
	client, err := queqiao.NewClient(queqiao.ClientOptions{
		RemoteAddr: serverAddr,
		Password:   "secret123",
		TLSConfig: &tls.Config{
			RootCAs:    testCertificatePool,
			ServerName: "127.0.0.1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.Start(context.Background())
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestTCPDataTransfer(t *testing.T) {
	echoAddr, stopEcho := setupEchoServer(t)
	defer stopEcho()
	serverAddr := startTestServer(t, directHandler{})
	client := newTestClient(t, serverAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx, M.ParseSocksaddr(echoAddr), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("Hello, Queqiao over sing-quic!")
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("reply = %q, want %q", reply, payload)
	}
}

func TestUDPDataTransfer(t *testing.T) {
	echoAddr, stopEcho := setupUDPEchoServer(t)
	defer stopEcho()
	serverAddr := startTestServer(t, directHandler{})
	client := newTestClient(t, serverAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	packetConn, err := client.ListenPacket(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()

	destination := M.ParseSocksaddr(echoAddr)
	payload := []byte("Hello, UDP over Queqiao!")
	buffer := buf.NewSize(len(payload))
	_, _ = buffer.Write(payload)
	if err = packetConn.WritePacket(buffer, destination); err != nil {
		t.Fatal(err)
	}
	readBuffer := buf.New()
	defer readBuffer.Release()
	_ = packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	readDestination, err := packetConn.ReadPacket(readBuffer)
	if err != nil {
		t.Fatal(err)
	}
	if readDestination.String() != destination.String() {
		t.Fatalf("reply from %s, want %s", readDestination, destination)
	}
	if string(readBuffer.Bytes()) != string(payload) {
		t.Fatalf("reply = %q, want %q", readBuffer.Bytes(), payload)
	}
}

// A client that finishes sending may still expect an answer: the FIN is a
// half-close on the wire, and it has to reach the destination as one.
func TestTCPHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		_, _ = conn.Write(append([]byte("after-eof:"), data...))
	}()
	serverAddr := startTestServer(t, directHandler{})
	client := newTestClient(t, serverAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx, M.ParseSocksaddr(listener.Addr().String()), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply) != "after-eof:request" {
		t.Fatalf("reply = %q", reply)
	}
}
