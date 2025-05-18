package pktconns

import (
	"net"
	// "time" // hopInterval is not used for faketcp, so time might not be needed directly here

	"github.com/ericcug/sing-quic/pktconns/faketcp" // Adjusted import path
)

// UDPProviderMaxDatagramSize is the default max datagram size for UDP.
// QUIC layer might further constrain this based on PMTU.
const UDPProviderMaxDatagramSize = 1472 // A common safe UDP payload size

// Abstracting the logger to be passed down
// type Logger is already defined in provider.go

// NewClientFakeTCPProvider creates a new ClientPacketConnProvider for FakeTCP.
func NewClientFakeTCPProvider() ClientPacketConnProvider {
	return &fakeTCPClientProvider{}
}

type fakeTCPClientProvider struct{}

func (p *fakeTCPClientProvider) Provide(serverAddr string, logger Logger) (net.PacketConn, net.Addr, error) {
	// The "network" for faketcp is typically "tcp" as it mimics TCP addressing.
	conn, err := faketcp.Dial("tcp", serverAddr, logger)
	if err != nil {
		return nil, nil, err
	}
	// For faketcp.Dial, the resolvedAddr is effectively the TCP address it's "dialing" to.
	// The actual underlying net.PacketConn (linuxFakeTCPConn) will have its own local/remote addrs,
	// but from QUIC's perspective, it's connecting to 'serverAddr'.
	// We need to resolve serverAddr to a net.Addr that quic.Dial expects.
	// Since faketcp.Dial itself takes a string and resolves it internally for its control conn,
	// we can resolve it again here for returning, or have faketcp.Dial return it.
	// For simplicity, let's assume quic.Dial can work with the PacketConn and a target Addr string.
	// However, quic.Dial usually expects a resolved net.Addr.

	// Let's resolve the server address to return it as net.Addr
	// faketcp internally uses TCP addresses for its control connection.
	rAddr, err := net.ResolveTCPAddr("tcp", serverAddr)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, nil, err
	}
	return conn, rAddr, nil
}

func (p *fakeTCPClientProvider) Type() string {
	return "faketcp"
}

// NewServerFakeTCPProvider creates a new ServerPacketConnProvider for FakeTCP.
func NewServerFakeTCPProvider() ServerPacketConnProvider {
	return &fakeTCPServerProvider{}
}

type fakeTCPServerProvider struct{}

func (p *fakeTCPServerProvider) Provide(listenAddr string, logger Logger) (net.PacketConn, error) {
	// The "network" for faketcp is typically "tcp".
	return faketcp.Listen("tcp", listenAddr, logger)
}

func (p *fakeTCPServerProvider) Type() string {
	return "faketcp"
}

// --- UDP Providers ---

// NewClientUDPProvider creates a new ClientPacketConnProvider for standard UDP.
func NewClientUDPProvider() ClientPacketConnProvider {
	return &udpClientProvider{}
}

type udpClientProvider struct{}

func (p *udpClientProvider) Provide(serverAddr string, logger Logger) (net.PacketConn, net.Addr, error) {
	rAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		if logger != nil {
			logger.Errorf("udpProvider: failed to resolve UDP address %s: %v", serverAddr, err)
		}
		return nil, nil, err
	}
	conn, err := net.ListenUDP("udp", nil) // OS chooses local port
	if err != nil {
		if logger != nil {
			logger.Errorf("udpProvider: failed to listen on UDP: %v", err)
		}
		return nil, nil, err
	}
	if logger != nil {
		logger.Debugf("udpProvider: client UDP connection established, local %s", conn.LocalAddr())
	}
	return conn, rAddr, nil
}

func (p *udpClientProvider) Type() string {
	return "udp"
}

// NewServerUDPProvider creates a new ServerPacketConnProvider for standard UDP.
func NewServerUDPProvider() ServerPacketConnProvider {
	return &udpServerProvider{}
}

type udpServerProvider struct{}

func (p *udpServerProvider) Provide(listenAddr string, logger Logger) (net.PacketConn, error) {
	lAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		if logger != nil {
			logger.Errorf("udpProvider: failed to resolve UDP listen address %s: %v", listenAddr, err)
		}
		return nil, err
	}
	conn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		if logger != nil {
			logger.Errorf("udpProvider: failed to listen on UDP %s: %v", listenAddr, err)
		}
		return nil, err
	}
	if logger != nil {
		logger.Debugf("udpProvider: server UDP listener started on %s", conn.LocalAddr())
	}
	return conn, nil
}

func (p *udpServerProvider) Type() string {
	return "udp"
}
