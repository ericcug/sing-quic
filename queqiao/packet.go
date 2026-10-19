package queqiao

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

// UDPConn exposes one queqiao UDP association through both connection
// interfaces sing uses. The association is a net.PacketConn whose every packet
// names its own destination, so neither a fixed peer nor a deadline belongs to
// it; the embedding host bounds a session with its own idle timer.
type UDPConn struct {
	net.PacketConn
}

func newUDPPacketConn(packetConn net.PacketConn) *UDPConn {
	return &UDPConn{PacketConn: packetConn}
}

func (c *UDPConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, addr, err := c.ReadFrom(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNet(addr).Unwrap(), nil
}

func (c *UDPConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	// A name is carried as a name: the gateway resolves it at its own egress,
	// which is what keeps a destination's DNS answer on that side of the
	// tunnel.
	var address net.Addr = destination
	if destination.IsIP() {
		address = destination.UDPAddr()
	}
	_, err := c.WriteTo(buffer.Bytes(), address)
	return err
}

func (c *UDPConn) Upstream() any {
	return c.PacketConn
}

var (
	_ N.NetPacketConn = (*UDPConn)(nil)
	_ N.PacketConn    = (*UDPConn)(nil)
	_ net.PacketConn  = (*UDPConn)(nil)
)

// packetPipe is an in-memory bidirectional N.PacketConn pair that preserves
// per-packet destinations. A stream pipe loses those boundaries and names
// every packet after the pipe endpoint.
type packetPipe struct {
	recv      <-chan routedPacket
	send      chan<- routedPacket
	done      chan struct{}
	peerDone  <-chan struct{}
	closeOnce sync.Once
	deadline  pipe.Deadline
}

type routedPacket struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}

func newPacketPipe() (*packetPipe, *packetPipe) {
	aToB := make(chan routedPacket, 64)
	bToA := make(chan routedPacket, 64)
	aDone := make(chan struct{})
	bDone := make(chan struct{})
	a := &packetPipe{recv: bToA, send: aToB, done: aDone, peerDone: bDone, deadline: pipe.MakeDeadline()}
	b := &packetPipe{recv: aToB, send: bToA, done: bDone, peerDone: aDone, deadline: pipe.MakeDeadline()}
	return a, b
}

func (p *packetPipe) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case packet := <-p.recv:
		_, err := buffer.ReadOnceFrom(packet.buffer)
		packet.buffer.Release()
		return packet.destination, err
	case <-p.done:
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-p.peerDone:
		select {
		case packet := <-p.recv:
			_, err := buffer.ReadOnceFrom(packet.buffer)
			packet.buffer.Release()
			return packet.destination, err
		default:
			return M.Socksaddr{}, io.EOF
		}
	case <-p.deadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (p *packetPipe) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	select {
	case <-p.done:
		buffer.Release()
		return io.ErrClosedPipe
	case <-p.peerDone:
		buffer.Release()
		return io.ErrClosedPipe
	default:
	}
	select {
	case p.send <- routedPacket{buffer: buffer, destination: destination}:
		return nil
	case <-p.done:
		buffer.Release()
		return io.ErrClosedPipe
	case <-p.peerDone:
		buffer.Release()
		return io.ErrClosedPipe
	}
}

func (p *packetPipe) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)
		for {
			select {
			case packet := <-p.recv:
				packet.buffer.Release()
			default:
				return
			}
		}
	})
	return nil
}

func (p *packetPipe) LocalAddr() net.Addr                { return M.Socksaddr{} }
func (p *packetPipe) SetDeadline(t time.Time) error      { return os.ErrInvalid }
func (p *packetPipe) SetReadDeadline(t time.Time) error  { p.deadline.Set(t); return nil }
func (p *packetPipe) SetWriteDeadline(t time.Time) error { return os.ErrInvalid }
