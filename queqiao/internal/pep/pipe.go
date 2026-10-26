package pep

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/pipe"
)

// streamPipeChunks bounds one direction's queued chunks. Each chunk is at most
// one application write, and a flow's reader keeps the queue near empty; the
// depth exists so a slow reader costs memory instead of blocking the proxy.
const streamPipeChunks = 64

// streamPipe is an in-memory full-duplex connection with independent
// directions, so a half-close reaches the peer as EOF while the other
// direction keeps carrying data. That matters here because a queqiao flow's
// FIN is a half-close: a destination that answers after its client finished
// sending must still be able to answer.
type streamPipe struct {
	readChunks  chan []byte
	writeChunks chan []byte

	localDone       chan struct{}
	localWriteDone  chan struct{}
	remoteDone      <-chan struct{}
	remoteWriteDone <-chan struct{}

	readDeadline  pipe.Deadline
	writeDeadline pipe.Deadline

	// readMu guards unread, the tail of a chunk the caller's buffer could not
	// accept. Every current use has a single reader per end; the mutex keeps
	// that assumption honest if a caller ever shares one.
	readMu sync.Mutex
	unread []byte

	writeOnce sync.Once
	closeOnce sync.Once
}

// NewStreamPipe returns the two ends of one in-memory connection. It differs
// from net.Pipe in two ways that matter here: writes are queued rather than
// synchronously matched, and each direction can be closed on its own, so the
// flow's FIN reaches the application as EOF while the answer still travels
// back.
func NewStreamPipe() (net.Conn, net.Conn) {
	return newStreamPipe()
}

func newStreamPipe() (net.Conn, net.Conn) {
	toB := make(chan []byte, streamPipeChunks)
	toA := make(chan []byte, streamPipeChunks)
	aDone, bDone := make(chan struct{}), make(chan struct{})
	aWriteDone, bWriteDone := make(chan struct{}), make(chan struct{})
	a := &streamPipe{
		readChunks:      toA,
		writeChunks:     toB,
		localDone:       aDone,
		localWriteDone:  aWriteDone,
		remoteDone:      bDone,
		remoteWriteDone: bWriteDone,
		readDeadline:    pipe.MakeDeadline(),
		writeDeadline:   pipe.MakeDeadline(),
	}
	b := &streamPipe{
		readChunks:      toB,
		writeChunks:     toA,
		localDone:       bDone,
		localWriteDone:  bWriteDone,
		remoteDone:      aDone,
		remoteWriteDone: aWriteDone,
		readDeadline:    pipe.MakeDeadline(),
		writeDeadline:   pipe.MakeDeadline(),
	}
	return a, b
}

func (p *streamPipe) Read(b []byte) (int, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	// A chunk the previous caller buffer could not accept is delivered first:
	// its bytes belong to this stream whether or not the next buffer is any
	// larger.
	if len(p.unread) > 0 {
		n := copy(b, p.unread)
		p.unread = p.unread[n:]
		return n, nil
	}
	for {
		// Closure and an already-passed deadline report themselves before
		// anything is taken, the same order sing's own pipe uses.
		select {
		case <-p.localDone:
			return 0, io.ErrClosedPipe
		case <-p.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		default:
		}
		// Buffered chunks outlive the peer's write half-close, so they are
		// drained before EOF is reported.
		select {
		case chunk := <-p.readChunks:
			return p.deliverChunk(b, chunk), nil
		default:
		}
		select {
		case chunk := <-p.readChunks:
			return p.deliverChunk(b, chunk), nil
		case <-p.remoteWriteDone:
			select {
			case chunk := <-p.readChunks:
				return p.deliverChunk(b, chunk), nil
			default:
			}
			return 0, io.EOF
		case <-p.remoteDone:
			select {
			case chunk := <-p.readChunks:
				return p.deliverChunk(b, chunk), nil
			default:
			}
			return 0, io.EOF
		case <-p.localDone:
			return 0, io.ErrClosedPipe
		case <-p.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// deliverChunk copies what b accepts and keeps the rest for the next Read.
// A chunk larger than the caller's buffer is the ordinary case, not an
// exception: a reassembler on the receive side merges whatever arrived
// contiguously into one write, and the application above reads with its own
// smaller buffers. Dropping the tail -- what a bare copy did -- was silent
// data corruption in both directions, and net.Conn's contract for a short
// Read is precisely that the remaining bytes stay available.
func (p *streamPipe) deliverChunk(b, chunk []byte) int {
	n := copy(b, chunk)
	if n < len(chunk) {
		p.unread = chunk[n:]
	}
	return n
}

func (p *streamPipe) Write(b []byte) (int, error) {
	// Closure and an already-passed deadline are checked before the fast path
	// so a closed connection cannot accept writes no reader will ever take.
	select {
	case <-p.localDone:
		return 0, io.ErrClosedPipe
	case <-p.localWriteDone:
		return 0, io.ErrClosedPipe
	case <-p.remoteDone:
		return 0, io.ErrClosedPipe
	case <-p.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if len(b) == 0 {
		// A zero-length write carries no byte and no boundary. Queueing an
		// empty chunk would make the peer's Read return (0, nil), which is
		// neither data nor EOF.
		return 0, nil
	}
	chunk := make([]byte, len(b))
	copy(chunk, b)
	for {
		select {
		case p.writeChunks <- chunk:
			return len(b), nil
		default:
		}
		select {
		case p.writeChunks <- chunk:
			return len(b), nil
		case <-p.remoteDone:
			return 0, io.ErrClosedPipe
		case <-p.localWriteDone:
			return 0, io.ErrClosedPipe
		case <-p.localDone:
			return 0, io.ErrClosedPipe
		case <-p.writeDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// CloseWrite ends this side's send direction. The peer reads EOF once it has
// consumed what was already queued, and may keep writing.
func (p *streamPipe) CloseWrite() error {
	p.writeOnce.Do(func() { close(p.localWriteDone) })
	return nil
}

func (p *streamPipe) Close() error {
	p.closeOnce.Do(func() { close(p.localDone) })
	return nil
}

func (p *streamPipe) LocalAddr() net.Addr {
	return pipeAddr{}
}

func (p *streamPipe) RemoteAddr() net.Addr {
	return pipeAddr{}
}

func (p *streamPipe) SetDeadline(t time.Time) error {
	p.readDeadline.Set(t)
	p.writeDeadline.Set(t)
	return nil
}

func (p *streamPipe) SetReadDeadline(t time.Time) error {
	p.readDeadline.Set(t)
	return nil
}

func (p *streamPipe) SetWriteDeadline(t time.Time) error {
	p.writeDeadline.Set(t)
	return nil
}

// pipeAddr is the unnamed peer of an in-memory connection, matching what
// sing's own pipe reports.
type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

var (
	_ net.Conn = (*streamPipe)(nil)
	_ interface {
		CloseWrite() error
	} = (*streamPipe)(nil)
)
