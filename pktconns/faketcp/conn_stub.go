//go:build !linux
// +build !linux

package faketcp

import (
	"errors"
	// "net" // Not strictly needed for the stub implementations if not returning a concrete type
	// No longer import "github.com/sagernet/sing-quic/pktconns"
)

func init() {
	dialInternal = func(network, address string, log logger) (FakeTCPConn, error) { // Changed logger type
		if log != nil {
			log.Errorf("faketcp.Dial: not supported on this platform for %s %s", network, address)
		}
		return nil, errors.New("faketcp: not supported on this platform")
	}

	listenInternal = func(network, address string, log logger) (FakeTCPConn, error) { // Changed logger type
		if log != nil {
			log.Errorf("faketcp.Listen: not supported on this platform for %s %s", network, address)
		}
		return nil, errors.New("faketcp: not supported on this platform")
	}
}
