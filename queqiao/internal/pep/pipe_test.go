package pep

import (
	"io"
	"os"
	"testing"
	"time"
)

// A chunk larger than the caller's buffer is the ordinary case: the receive
// side merges whatever arrived contiguously into one write, and sing-box
// reads with 8..64 KiB buffers while it copies with 32 KiB ones. The Read
// contract for a short return is that the remaining bytes stay available,
// not that they vanish.
func TestStreamPipeReadKeepsATailLargerThanTheBuffer(t *testing.T) {
	a, b := newStreamPipe()
	defer a.Close()
	defer b.Close()

	chunk := make([]byte, 64*1024)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	if n, err := a.Write(chunk); err != nil || n != len(chunk) {
		t.Fatalf("write: n=%d err=%v", n, err)
	}

	half := len(chunk) / 2
	first := make([]byte, half)
	if n, err := b.Read(first); err != nil || n != half {
		t.Fatalf("first read: n=%d err=%v, want %d", n, err, half)
	}
	second := make([]byte, len(chunk))
	b.SetReadDeadline(time.Now().Add(time.Second))
	n, err := b.Read(second)
	if err != nil {
		t.Fatalf("second read: %v -- the tail was discarded", err)
	}
	if n != half {
		t.Fatalf("second read: n=%d, want the remaining %d", n, half)
	}
	for i := range first {
		if first[i] != chunk[i] {
			t.Fatalf("first half diverged at %d", i)
		}
	}
	for i := 0; i < n; i++ {
		if second[i] != chunk[half+i] {
			t.Fatalf("second half diverged at %d", i)
		}
	}
}

// Many short reads reassemble one chunk exactly.
func TestStreamPipeReadReassemblesAcrossShortBuffers(t *testing.T) {
	a, b := newStreamPipe()
	defer a.Close()
	defer b.Close()

	chunk := make([]byte, 1000)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	if _, err := a.Write(chunk); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 0, len(chunk))
	one := make([]byte, 1)
	for len(got) < len(chunk) {
		b.SetReadDeadline(time.Now().Add(time.Second))
		n, err := b.Read(one)
		if err != nil {
			t.Fatalf("read at %d: %v", len(got), err)
		}
		got = append(got, one[:n]...)
	}
	for i := range chunk {
		if got[i] != chunk[i] {
			t.Fatalf("reassembled bytes diverged at %d", i)
		}
	}
}

// Close must unblock a Write stalled on a full queue: net.Conn requires
// blocked operations to return errors after Close, and the writer here owns
// the goroutine that would otherwise leak for the life of the flow.
func TestStreamPipeCloseUnblocksAStalledWrite(t *testing.T) {
	a, b := newStreamPipe()
	defer b.Close()

	stalled := make(chan error, 1)
	go func() {
		chunk := make([]byte, 1024)
		for {
			if _, err := a.Write(chunk); err != nil {
				stalled <- err
				return
			}
		}
	}()
	// Fill the queue well past its depth so the writer is parked in the
	// blocking select.
	drain := make([]byte, 1)
	for i := 0; i < streamPipeChunks*2+8; i++ {
		b.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := b.Read(drain); err != nil {
			t.Fatalf("drain read %d: %v", i, err)
		}
	}
	a.Close()
	select {
	case err := <-stalled:
		if err != io.ErrClosedPipe {
			t.Fatalf("stalled write returned %v, want io.ErrClosedPipe", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock a stalled Write")
	}
}

// Writes after Close, after a passed write deadline, and of zero length are
// refused or are no-ops rather than being queued for a reader that no longer
// exists.
func TestStreamPipeWriteClosureSemantics(t *testing.T) {
	a, b := newStreamPipe()
	defer b.Close()
	a.Close()
	if _, err := a.Write([]byte("x")); err != io.ErrClosedPipe {
		t.Fatalf("write after Close: %v, want io.ErrClosedPipe", err)
	}

	c, d := newStreamPipe()
	defer d.Close()
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := c.Write([]byte("x")); err != os.ErrDeadlineExceeded {
		t.Fatalf("write after deadline: %v, want os.ErrDeadlineExceeded", err)
	}

	e, f := newStreamPipe()
	defer e.Close()
	defer f.Close()
	if n, err := e.Write(nil); err != nil || n != 0 {
		t.Fatalf("empty write: n=%d err=%v", n, err)
	}
	// The empty write must not have enqueued anything.
	f.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	one := make([]byte, 1)
	if n, err := f.Read(one); n != 0 || err == nil {
		t.Fatalf("empty write queued a chunk: n=%d err=%v", n, err)
	}
}

// Half-close keeps the answer direction alive while EOF is reported for the
// closed one, and buffered chunks are drained before that EOF.
func TestStreamPipeHalfCloseDrainsBeforeEOF(t *testing.T) {
	a, b := newStreamPipe()
	defer a.Close()
	defer b.Close()

	payload := []byte("request")
	if _, err := a.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := a.(*streamPipe).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("drained %q, want %q", got, payload)
	}
	one := make([]byte, 1)
	if _, err := b.Read(one); err != io.EOF {
		t.Fatalf("read after peer half-close: %v, want io.EOF", err)
	}
	// The half-closed side still receives.
	if _, err := b.Write([]byte("answer")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("answer"))
	if _, err := io.ReadFull(a, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "answer" {
		t.Fatalf("reply = %q", reply)
	}
}


