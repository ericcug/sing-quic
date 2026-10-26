package portmux

import (
	"net"
	"testing"
)

// Every unauthenticated datagram on a hop port names its own source, so an
// unbounded return-socket table is memory any spoofed packet can claim. Two
// generations bound what is held, and primary-port packets claim no slot at
// all because primary is the default when no route is recorded.
func TestServerPortMuxBoundsTheRouteTable(t *testing.T) {
	primary := &net.UDPConn{}
	hop := &net.UDPConn{}
	m := &ServerPortMux{primary: primary, secondaries: []*net.UDPConn{hop}}

	for port := 1; port <= maxServerRoutes*3+100; port++ {
		m.rememberRoute(&net.UDPAddr{IP: net.IPv4(10, 0, byte(port>>8), byte(port)), Port: port}, hop)
	}
	m.routesMu.RLock()
	held := len(m.current) + len(m.previous)
	m.routesMu.RUnlock()
	if held > 2*maxServerRoutes {
		t.Fatalf("route table holds %d entries, want at most %d", held, 2*maxServerRoutes)
	}
	// A recent peer still resolves to the hop socket.
	lastPort := maxServerRoutes*3 + 100
	last := &net.UDPAddr{IP: net.IPv4(10, 0, byte(lastPort>>8), byte(lastPort)), Port: lastPort}
	if got := m.pickConn(last); got != hop {
		t.Fatal("newest peer did not resolve to the hop socket")
	}
	// Returning to the primary port clears the entry rather than storing one.
	m.rememberRoute(last, primary)
	if got := m.pickConn(last); got != primary {
		t.Fatal("primary-port arrival did not clear the hop route")
	}
}
