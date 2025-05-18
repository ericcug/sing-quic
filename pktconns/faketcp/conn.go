package faketcp

import (
	"net"
	"syscall" // Added for syscall.RawConn
	"time"
)

// logger is an internal interface for logging within the faketcp package.
// It should be compatible with pktconns.Logger.
type logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

const (
	// MaxIPPacketSize is a general constant for IP packet buffer allocations.
	// Actual QUIC payload size should be configured at the QUIC layer (e.g., to 1440).
	MaxIPPacketSize = 2048 // Consistent with Hysteria's buffer, safe for typical MTUs + headers
	// FlowIdleTimeout is the duration after which an idle faketcp flow state is cleaned up.
	FlowIdleTimeout = time.Minute
)

// FakeTCPConn represents a packet connection that emulates TCP.
// It will be implemented by platform-specific types.
type FakeTCPConn interface {
	net.PacketConn
	// SetDSCP sets the DSCP field for packets sent on this connection.
	SetDSCP(dscp int) error
	// SyscallConn returns the underlying raw connection.
	// Using syscall.RawConn as it's more standard for this purpose than net.Conn for raw access.
	SyscallConn() (syscall.RawConn, error)
}

// Dial connects to the remote TCP-like endpoint.
// Implemented in conn_linux.go and conn_stub.go.
// The actual implementation will be in platform-specific files named 'dial'
func Dial(network, address string, log logger) (FakeTCPConn, error) { // Changed logger type
	return dialInternal(network, address, log)
}

// Listen starts listening on a local TCP-like endpoint.
// Implemented in conn_linux.go and conn_stub.go.
// The actual implementation will be in platform-specific files named 'listen'
func Listen(network, address string, log logger) (FakeTCPConn, error) { // Changed logger type
	return listenInternal(network, address, log)
}

// dialInternal and listenInternal will be the actual functions implemented
// by conn_linux.go and conn_stub.go. This avoids "unused" warnings for
// Dial and Listen if they were directly the platform-specific ones.
var dialInternal func(network, address string, log logger) (FakeTCPConn, error)   // Changed logger type
var listenInternal func(network, address string, log logger) (FakeTCPConn, error) // Changed logger type
