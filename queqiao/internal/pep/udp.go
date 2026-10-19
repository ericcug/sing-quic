package pep

// This file implements the SOCKS5 UDP-associate data plane. UDP packets are
// carried as individual authenticated queqiao TypePacket frames, so packet
// boundaries survive whichever substrate carries them.
//
// Where the lane's QUIC connection negotiated DATAGRAM in both directions,
// those frames go over the connection's datagrams; otherwise -- a TLS/TCP
// lane, a peer without datagram support, or a datagram the transport refuses
// -- they go over the control stream. QUIC's transport negotiation tells both
// endpoints whether the datagram substrate is available.
//
// The substrate is chosen for its semantics rather than its speed. An
// application that chose UDP has already decided a late packet is worse than
// a lost one, and a stream gives it the opposite: every loss is retransmitted
// and holds up every packet behind it until it arrives. That is the wrong
// trade for DNS, for QUIC inside this tunnel, and for anything interactive.
// What it costs is that gaps are now normal, which is why the sequence number
// is read through a replay window below rather than being required to be the
// next one.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/queqiao/internal/protocol"
	"github.com/sagernet/sing-quic/queqiao/internal/session"
	"github.com/sagernet/sing-quic/queqiao/internal/udperr"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/pipe"
)

// maxUDPDatagramBuffer bounds one inbound datagram read from the router.
const maxUDPDatagramBuffer = 65535

type udpCounters struct {
	up   atomic.Uint64
	down atomic.Uint64
}

// packetWindowWidth is how far out of order a UDP packet may arrive and still
// be placed. It bounds the memory this costs to one word per direction.
const packetWindowWidth = 64

// packetWindow decides whether a UDP packet has already been delivered,
// without requiring it to arrive in order.
//
// On the control stream the sequence numbers arrived in order and could not
// gap, so an association simply demanded the next one and failed on anything
// else. Over datagrams neither holds: a lost packet is not retransmitted, and
// a later one can overtake an earlier one. A gap is then the ordinary case --
// it is the loss the application asked for by choosing UDP -- and failing the
// association on it would turn every dropped packet into a reconnect.
//
// So the sequence is used for what it can still decide. This is an
// anti-replay window: the highest sequence seen and a bitmap of those just
// below it. Above the window advances it, inside it is accepted once, below
// it is too old to place and is dropped. A peer cannot make it hold anything.
type packetWindow struct {
	highest uint64
	seen    uint64
	started bool
}

func (w *packetWindow) admit(seq uint64) bool {
	if !w.started {
		w.started, w.highest, w.seen = true, seq, 1
		return true
	}
	switch {
	case seq > w.highest:
		if shift := seq - w.highest; shift >= packetWindowWidth {
			w.seen = 0
		} else {
			w.seen <<= shift
		}
		w.highest = seq
		w.seen |= 1
		return true
	case w.highest-seq >= packetWindowWidth:
		return false
	default:
		bit := uint64(1) << (w.highest - seq)
		if w.seen&bit != 0 {
			return false
		}
		w.seen |= bit
		return true
	}
}

// ListenPacket creates a UDP association and returns it as a native
// net.PacketConn.
func (c *Client) ListenPacket(ctx context.Context, onClose func(error)) (net.PacketConn, error) {
	if !c.admitPendingOpen() {
		return nil, errors.New("local pending-open limit reached")
	}
	assoc, err := c.openUDPAssociation(ctx)
	c.releasePendingOpen()
	if err != nil {
		return nil, err
	}
	return newClientUDPPacketConn(c, assoc, onClose), nil
}

// readWaitQueue bounds how many inbound packets wait for the application.
const readWaitQueue = 64

type clientUDPPacketConn struct {
	client       *Client
	association  *udpAssociation
	frames       <-chan protocol.Frame
	frameErr     <-chan error
	cancel       context.CancelFunc
	ctx          context.Context
	seq          atomic.Uint64
	readChan     chan readResult
	readDeadline pipe.Deadline
	onClose      func(error)
	closeOnce    sync.Once
}

type readResult struct {
	destination net.Addr
	payload     []byte
	err         error
}

func newClientUDPPacketConn(c *Client, assoc *udpAssociation, onClose func(error)) *clientUDPPacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	frames, frameErr := udpFrames(ctx, assoc.lane.fc, assoc.flowID)
	conn := &clientUDPPacketConn{
		client:       c,
		association:  assoc,
		frames:       frames,
		frameErr:     frameErr,
		ctx:          ctx,
		cancel:       cancel,
		readChan:     make(chan readResult, readWaitQueue),
		readDeadline: pipe.MakeDeadline(),
		onClose:      onClose,
	}
	go conn.readLoop()
	return conn
}

// readLoop decouples the association's frame stream from the application's
// read cadence, and only resolves a destination the server named by name
// when the peer itself answers with one.
func (c *clientUDPPacketConn) readLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case err := <-c.frameErr:
			c.notifyClose(err)
			select {
			case c.readChan <- readResult{err: err}:
			case <-c.ctx.Done():
			}
			return
		case frame, ok := <-c.frames:
			if !ok {
				c.notifyClose(net.ErrClosed)
				select {
				case c.readChan <- readResult{err: net.ErrClosed}:
				case <-c.ctx.Done():
				}
				return
			}
			if frame.Header.Type != protocol.TypePacket {
				continue
			}
			destination, payload, err := session.DecodeUDPPacket(frame.Payload)
			if err != nil {
				continue
			}
			socksaddr, parseErr := parseCanonicalAddress(destination)
			if parseErr != nil {
				continue
			}
			select {
			case c.readChan <- readResult{destination: socksaddr, payload: payload}:
			case <-c.ctx.Done():
				return
			}
		}
	}
}

// parseCanonicalAddress converts an already validated canonical destination
// into a net.Addr without a DNS lookup: a numeric destination becomes its
// *net.UDPAddr and a name stays a name for the caller to resolve.
func parseCanonicalAddress(destination string) (net.Addr, error) {
	if _, err := session.EncodeDestination(destination); err != nil {
		return nil, err
	}
	socksaddr := M.ParseSocksaddr(destination)
	if socksaddr.IsDomain() {
		return socksaddr, nil
	}
	return socksaddr.UDPAddr(), nil
}

func (c *clientUDPPacketConn) notifyClose(err error) {
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose(err)
		}
	})
}

func (c *clientUDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		select {
		case <-c.ctx.Done():
			return 0, nil, net.ErrClosed
		case result := <-c.readChan:
			if result.err != nil {
				return 0, nil, result.err
			}
			n = copy(p, result.payload)
			return n, result.destination, nil
		case <-c.readDeadline.Wait():
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

func (c *clientUDPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	payload, err := session.EncodeUDPPacket(addr.String(), p)
	if err != nil {
		return 0, err
	}
	seq := c.seq.Add(1) - 1
	frame := protocol.Frame{
		Header: protocol.Header{
			Version:    protocol.Version,
			Type:       protocol.TypePacket,
			SessionID:  c.association.lane.sessionID,
			FlowID:     c.association.flowID,
			Sequence:   seq,
			Class:      protocol.ClassInteractive,
			PayloadLen: uint32(len(payload)),
		},
		Payload: payload,
	}
	if err := c.association.lane.fc.WriteContext(c.ctx, frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *clientUDPPacketConn) Close() error {
	c.notifyClose(nil)
	c.cancel()
	_ = c.association.lane.fc.Write(protocol.Frame{
		Header: protocol.Header{
			Version:   protocol.Version,
			Type:      protocol.TypeClose,
			Flags:     protocol.FlagFin,
			SessionID: c.association.lane.sessionID,
			FlowID:    c.association.flowID,
		},
	})
	return c.association.lane.fc.Close()
}

func (c *clientUDPPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

// SetDeadline applies to reads only, because a write returns as soon as the
// frame is queued on the lane.
func (c *clientUDPPacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *clientUDPPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *clientUDPPacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

// udpAssociation is what an open produced: the lane and the flow it belongs to.
type udpAssociation struct {
	lane   *authenticatedLane
	flowID uint64
}

type udpAssociationOpenTransportError struct {
	operation string
	err       error
}

func (e *udpAssociationOpenTransportError) Error() string {
	return e.operation + ": " + e.err.Error()
}

func (e *udpAssociationOpenTransportError) Unwrap() error { return e.err }

// openUDPAssociation opens one UDP association over the shared QUIC
// generation. A transport failure retires that generation, and the retry
// therefore dials a fresh one.
func (c *Client) openUDPAssociation(ctx context.Context) (*udpAssociation, error) {
	association, err := c.openUDPAssociationLane(ctx)
	if err == nil || ctx.Err() != nil {
		return association, err
	}
	var transportErr *udpAssociationOpenTransportError
	if !errors.As(err, &transportErr) {
		return nil, err
	}
	retry, retryErr := c.openUDPAssociationLane(ctx)
	if retryErr != nil {
		return nil, fmt.Errorf("UDP association open failed (%v); retry failed: %w", err, retryErr)
	}
	return retry, nil
}

func (c *Client) openUDPAssociationLane(ctx context.Context) (*udpAssociation, error) {
	lane, err := c.chooseAuthenticatedLane(ctx)
	if err != nil {
		return nil, err
	}
	flowID, err := randomFlowID()
	if err != nil {
		_ = lane.fc.Close()
		return nil, err
	}
	payload := session.UDPAssociationMarker
	_ = lane.outer.SetDeadline(time.Now().Add(handshakeBound(lane.outer, c.cfg.HandshakeTimeout)))
	if err := lane.fc.Write(protocol.Frame{Header: protocol.Header{
		Version: protocol.Version, Type: protocol.TypeOpen, SessionID: lane.sessionID,
		FlowID: flowID, Class: protocol.ClassInteractive,
	}, Payload: payload}); err != nil {
		return nil, failUDPAssociationOpenLane(lane, "send UDP association open", err)
	}
	response, err := lane.fc.Read()
	if err != nil {
		return nil, failUDPAssociationOpenLane(lane, "read UDP association acknowledgement", err)
	}
	if response.Header.SessionID != lane.sessionID || response.Header.FlowID != flowID {
		_ = lane.fc.Close()
		return nil, errors.New("UDP association acknowledgement identity mismatch")
	}
	if response.Header.Type == protocol.TypeReset {
		_ = lane.fc.Close()
		return nil, errors.New("remote UDP association rejected")
	}
	if response.Header.Type != protocol.TypeOpenOK {
		_ = lane.fc.Close()
		return nil, errors.New("invalid UDP association acknowledgement")
	}
	_ = lane.outer.SetDeadline(time.Time{})
	return &udpAssociation{lane: lane, flowID: flowID}, nil
}

func failUDPAssociationOpenLane(lane *authenticatedLane, operation string, err error) error {
	transportErr := &udpAssociationOpenTransportError{operation: operation, err: err}
	if lane != nil && lane.fc != nil {
		if observer, ok := lane.fc.transport().(interface{ transportFailed(error) }); ok {
			observer.transportFailed(transportErr)
		}
		_ = lane.fc.Close()
	}
	return transportErr
}

// udpFrames merges the two substrates an association's frames can arrive on
// into one channel.
//
// They cannot be read from one call. The control stream is read synchronously
// under the caller's deadline, and the datagrams are delivered by the
// connection's demultiplexer to whichever flow they name -- so one reader per
// substrate, both feeding the loop that does not care which it came from.
//
// The stream reader outlives a cancelled context by up to one blocked read.
// That is the same bound the association's other workers have and is closed by
// the lane's Close on every exit path, which is what actually unblocks it.
func udpFrames(ctx context.Context, fc *frameConn, flowID uint64) (<-chan protocol.Frame, <-chan error) {
	queueFrames := 64
	if fc.bulkQueueFrames > 0 && fc.bulkQueueFrames < queueFrames {
		queueFrames = fc.bulkQueueFrames
	}
	if queueFrames < 2 {
		queueFrames = 2
	}
	frames := make(chan protocol.Frame, queueFrames)
	errs := make(chan error, 1)
	go func() {
		for {
			frame, err := fc.Read()
			if err != nil {
				select {
				case errs <- err:
				default:
				}
				return
			}
			select {
			case frames <- frame:
			case <-ctx.Done():
				return
			}
			// A final ACK is the peer's terminal association event. Stop after
			// publishing it so a following stream EOF cannot win the independent
			// error-channel select and turn a clean close into lane failure. RESET
			// is terminal too; its frame carries the useful failure reason.
			if (frame.Header.Type == protocol.TypeAck && frame.Header.Flags == protocol.FlagAckFinal) || frame.Header.Type == protocol.TypeReset {
				return
			}
		}
	}()
	if bulk := fc.bulkFrames(flowID); bulk != nil {
		go func() {
			for {
				select {
				case frame, ok := <-bulk:
					if !ok {
						// The datagram substrate ending is not the
						// association ending: the control stream still
						// carries the close handshake, and a packet that
						// was on a dead datagram path was lost, which is
						// what a UDP packet is allowed to be.
						return
					}
					select {
					case frames <- frame:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	return frames, errs
}

func (s *Server) handleUDPAssociation(ctx context.Context, conn streamConn, fc *frameConn, user string, sessionID [16]byte, flowID uint64) {
	packetConn, err := s.cfg.DestinationPolicy.ListenPacket(ctx, user)
	if err != nil {
		_ = fc.Write(protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeReset, SessionID: sessionID, FlowID: flowID, Class: protocol.ClassInteractive}, Payload: session.ResetPayload(session.ResetTransport, "UDP relay unavailable")})
		s.cfg.Logger.Debug("UDP relay unavailable", "error", err)
		return
	}
	defer packetConn.Close()

	openOK := protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeOpenOK, SessionID: sessionID, FlowID: flowID, Class: protocol.ClassInteractive}}
	if err := fc.Write(openOK); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	assocCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	frames := make(chan protocol.Frame, 32)
	frameErr := make(chan error, 1)
	go func() {
		for {
			frame, readErr := fc.Read()
			if readErr != nil {
				select {
				case frameErr <- readErr:
				case <-assocCtx.Done():
				}
				return
			}
			select {
			case frames <- frame:
			case <-assocCtx.Done():
				return
			}
			// A graceful UDP dissociation is terminal. Stop reading immediately
			// after queueing CLOSE so a following transport EOF cannot race the
			// CLOSE event and turn a clean association into a false failure.
			if frame.Header.Type == protocol.TypeClose {
				return
			}
		}
	}()
	// The connection's datagrams feed the same channel. Only packets arrive
	// there -- the close handshake and every other control frame stay on the
	// stream -- so the loop below reads one channel and does not have to know
	// which substrate a packet crossed on.
	if bulk := fc.bulkFrames(flowID); bulk != nil {
		defer fc.releaseBulk(flowID)
		go func() {
			for {
				select {
				case frame, ok := <-bulk:
					if !ok {
						return
					}
					select {
					case frames <- frame:
					case <-assocCtx.Done():
						return
					}
				case <-assocCtx.Done():
					return
				}
			}
		}()
	}
	packets := make(chan udpDatagram, 32)
	packetErr := make(chan error, 1)
	packetBuffer := buf.NewSize(maxUDPDatagramBuffer)
	defer packetBuffer.Release()
	go func() {
		for {
			packetBuffer.Reset()
			destination, readErr := packetConn.ReadPacket(packetBuffer)
			if readErr != nil {
				select {
				case packetErr <- readErr:
				case <-assocCtx.Done():
				}
				return
			}
			payload := append([]byte(nil), packetBuffer.Bytes()...)
			select {
			case packets <- udpDatagram{destination: destination, payload: payload}:
			case <-assocCtx.Done():
				return
			}
		}
	}()

	var counters udpCounters
	var window packetWindow
	var replySequence uint64
	s.metrics.FlowStarted()
	idleTimer := time.NewTimer(s.cfg.FlowIdleTimeout)
	lifetimeTimer := time.NewTimer(s.cfg.FlowMaxLifetime)
	defer idleTimer.Stop()
	defer lifetimeTimer.Stop()
	failed := false
	var endErr error
	resetIdle := func() {
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
		idleTimer.Reset(s.cfg.FlowIdleTimeout)
	}
	for {
		select {
		case frame, ok := <-frames:
			if !ok {
				goto done
			}
			if frame.Header.SessionID != sessionID || frame.Header.FlowID != flowID {
				endErr = errors.New("invalid UDP association frame")
				failed = true
				goto done
			}
			if frame.Header.Type == protocol.TypeClose {
				if frame.Header.Flags != protocol.FlagFin || len(frame.Payload) != 0 || frame.Header.Sequence != 0 {
					endErr = errors.New("invalid UDP association close")
					failed = true
				}
				if !failed {
					_ = fc.WriteContext(assocCtx, protocol.Frame{Header: protocol.Header{
						Version: protocol.Version, Type: protocol.TypeAck, Flags: protocol.FlagAckFinal,
						SessionID: sessionID, FlowID: flowID, Sequence: 0, Class: protocol.ClassInteractive,
					}})
				}
				goto done
			}
			if frame.Header.Type != protocol.TypePacket || frame.Header.Flags != 0 {
				endErr = errors.New("invalid UDP association frame")
				failed = true
				goto done
			}
			destination, payload, decodeErr := session.DecodeUDPPacket(frame.Payload)
			if decodeErr != nil {
				endErr = decodeErr
				failed = true
				goto done
			}
			if !window.admit(frame.Header.Sequence) {
				// A duplicate, or one so far behind it cannot be told from
				// one. Dropping it is not an error: over datagrams that is
				// the substrate behaving normally, and failing the
				// association would turn every reordered packet into a
				// reconnect.
				continue
			}
			packet := buf.NewSize(len(payload))
			_, writeErr := packet.Write(payload)
			if writeErr != nil {
				packet.Release()
				continue
			}
			if writeErr = packetConn.WritePacket(packet, M.ParseSocksaddr(destination)); writeErr != nil {
				if udperr.Transient(writeErr) {
					continue
				}
				endErr = writeErr
				failed = true
				s.cfg.Logger.Debug("UDP relay write ended", "error", writeErr)
				goto done
			}
			counters.up.Add(uint64(len(payload)))
			resetIdle()
		case packet := <-packets:
			payload, encodeErr := session.EncodeUDPPacket(packet.destination.String(), packet.payload)
			if encodeErr != nil {
				continue
			}
			if writeErr := fc.WriteContext(assocCtx, protocol.Frame{Header: protocol.Header{
				Version: protocol.Version, Type: protocol.TypePacket, SessionID: sessionID,
				FlowID: flowID, Sequence: replySequence, Class: protocol.ClassInteractive,
			}, Payload: payload}); writeErr != nil {
				endErr = writeErr
				failed = true
				goto done
			}
			replySequence++
			counters.down.Add(uint64(len(packet.payload)))
			resetIdle()
		case err := <-frameErr:
			if assocCtx.Err() != nil {
				goto done
			}
			endErr = err
			failed = true
			s.cfg.Logger.Debug("UDP relay frame reader ended", "error", err)
			goto done
		case err := <-packetErr:
			if assocCtx.Err() != nil {
				goto done
			}
			endErr = err
			failed = true
			s.cfg.Logger.Debug("UDP relay packet reader ended", "error", err)
			goto done
		case <-idleTimer.C:
			s.metrics.FlowTimeout()
			endErr = errors.New("UDP association idle timeout")
			failed = true
			goto done
		case <-lifetimeTimer.C:
			s.metrics.FlowTimeout()
			endErr = errors.New("UDP association lifetime exceeded")
			failed = true
			goto done

		case <-assocCtx.Done():
			goto done
		}
	}
done:
	if endErr != nil && failed {
		s.cfg.Logger.Debug("UDP association ended", "error", endErr)
	}
	s.metrics.FlowFinished(counters.up.Load(), counters.down.Load(), failed)
	_ = conn.Close()
}

type udpDatagram struct {
	destination M.Socksaddr
	payload     []byte
}
