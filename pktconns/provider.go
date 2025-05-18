package pktconns

import (
	"net"
)

// Logger defines a generic logging interface compatible with sing-quic's logger.
// This should be adapted if sing-quic uses a specific logging library or interface.
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	// Add other necessary methods like Debug, Info, Warn, Error if they exist
}

// ClientPacketConnProvider is responsible for creating a net.PacketConn for the client.
type ClientPacketConnProvider interface {
	// Provide creates and returns a net.PacketConn and the resolved server address.
	Provide(serverAddr string, logger Logger) (conn net.PacketConn, resolvedAddr net.Addr, err error)
	// Type returns a string identifier for the provider, e.g., "udp", "faketcp".
	Type() string
}

// ServerPacketConnProvider is responsible for creating a net.PacketConn for the server.
type ServerPacketConnProvider interface {
	// Provide creates and returns a net.PacketConn to listen on.
	Provide(listenAddr string, logger Logger) (conn net.PacketConn, err error)
	// Type returns a string identifier for the provider, e.g., "udp", "faketcp".
	Type() string
}
