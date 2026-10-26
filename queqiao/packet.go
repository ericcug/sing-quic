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
	// writeDeadline bounds a WritePacket the peer is not draining. Without
	// one, a stopped reader on the other end parks the writer forever, and
	// the writer here is often the only goroutine that also watches the
	// association's idle and lifetime timers.
	writeDeadline pipe.Deadline
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
	a := &packetPipe{recv: bToA, send: aToB, done: aDone, peerDone: bDone, deadline: pipe.MakeDeadline(), writeDeadline: pipe.MakeDeadline()}
	b := &packetPipe{recv: aToB, send: bToA, done: bDone, peerDone: aDone, deadline: pipe.MakeDeadline(), writeDeadline: pipe.MakeDeadline()}
	return a, b
}

func (p *packetPipe) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case packet := <-p.recv:
		// Written rather than ReadOnceFrom: an empty datagram is a legal
		// packet, and reading one from an empty buffer surfaces as io.EOF
		// -- which the caller above treats as the association ending, over
		// a peer that sent nothing worse than a zero-length datagram.
		_, err := buffer.Write(packet.buffer.Bytes())
		packet.buffer.Release()
		return packet.destination, err
	case <-p.done:
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-p.peerDone:
		select {
		case packet := <-p.recv:
			_, err := buffer.Write(packet.buffer.Bytes())
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
	case <-p.writeDeadline.Wait():
		buffer.Release()
		return os.ErrDeadlineExceeded
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
	case <-p.writeDeadline.Wait():
		buffer.Release()
		return os.ErrDeadlineExceeded
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
func (p *packetPipe) SetDeadline(t time.Time) error {
	p.deadline.Set(t)
	p.writeDeadline.Set(t)
	return nil
}
func (p *packetPipe) SetReadDeadline(t time.Time) error      { p.deadline.Set(t); return nil }
func (p *packetPipe) SetWriteDeadline(t time.Time) error     { p.writeDeadline.Set(t); return nil }
