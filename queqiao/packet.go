package queqiao

import "net"

type Addr struct {
	Target string
}

func (a Addr) Network() string {
	return "udp"
}

func (a Addr) String() string {
	return a.Target
}

var _ net.Addr = Addr{}
