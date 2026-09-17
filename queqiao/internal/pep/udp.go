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
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/queqiao/internal/protocol"
	"github.com/sagernet/sing-quic/queqiao/internal/session"
	"github.com/sagernet/sing-quic/queqiao/internal/udperr"
)

const (
	udpReadPoll                = time.Second
	maxUDPReconnectAttempts    = 3
	udpReconnectInitialBackoff = 200 * time.Millisecond
	udpReconnectMaximumBackoff = 2 * time.Second
)

// errUDPAssociationCloseAck is kept distinct from nil so a peer-generated
// final acknowledgement cannot be mistaken for a transport failure. A clean
// SOCKS dissociation is the only normal path that should produce it.
var (
	errUDPAssociationCloseAck = errors.New("UDP association close acknowledged")
	errUDPControlClosed       = errors.New("SOCKS UDP control connection closed")
)

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

// ListenPacket creates a UDP association and returns a native net.PacketConn.
func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if !c.admitPendingOpen() {
		return nil, errors.New("local pending-open limit reached")
	}
	assoc, err := c.openUDPAssociation(ctx, nil)
	c.releasePendingOpen()
	if err != nil {
		return nil, err
	}
	return newClientUDPPacketConn(c, assoc), nil
}

type clientUDPPacketConn struct {
	client      *Client
	association *udpAssociation
	frames      <-chan protocol.Frame
	frameErr    <-chan error
	cancel      context.CancelFunc
	ctx         context.Context
	seq         atomic.Uint64
}

func newClientUDPPacketConn(c *Client, assoc *udpAssociation) *clientUDPPacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	frames, frameErr := udpFrames(ctx, assoc.lane.fc, assoc.flowID)
	return &clientUDPPacketConn{
		client:      c,
		association: assoc,
		frames:      frames,
		frameErr:    frameErr,
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (c *clientUDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		select {
		case <-c.ctx.Done():
			return 0, nil, net.ErrClosed
		case err := <-c.frameErr:
			return 0, nil, err
		case frame, ok := <-c.frames:
			if !ok {
				return 0, nil, net.ErrClosed
			}
			if frame.Header.Type != protocol.TypePacket {
				continue
			}
			dest, payload, err := session.DecodeUDPPacket(frame.Payload)
			if err != nil {
				continue
			}
			udpAddr, _ := net.ResolveUDPAddr("udp", dest)
			n = copy(p, payload)
			return n, udpAddr, nil
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

func (c *clientUDPPacketConn) SetDeadline(t time.Time) error {
	return c.association.lane.outer.SetDeadline(t)
}

func (c *clientUDPPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *clientUDPPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// rescueUDPAssociation opens a replacement association, offering the token of
// the relay the failed one was using. Every attempt offers the same token: the
// server consumes it on the first attempt that reaches it, so a later attempt
// simply gets a fresh relay, which is the outcome that existed before resume.
// The failed established lane is not global path evidence: a peer restart or
// application close looks identical there. AUTO nevertheless rescues this flow
// directly over TCP instead of waiting for a fresh QUIC dial to time out. New
// flows keep probing QUIC and make the endpoint-level path observation.
func (c *Client) rescueUDPAssociation(ctx context.Context, controlClosed <-chan struct{}, resume []byte) (*udpAssociation, error) {
	var lastErr error
	for attempt := 0; attempt < maxUDPReconnectAttempts; attempt++ {
		if err := waitForUDPReconnect(ctx, controlClosed, udpReconnectBackoff(attempt)); err != nil {
			return nil, err
		}
		c.metrics.UDPAssociationReconnect()
		attemptCtx, attemptCancel := context.WithTimeout(ctx, c.cfg.DialTimeout+c.cfg.HandshakeTimeout)
		association, err := c.openUDPAssociationMode(attemptCtx, resume, false, true)
		attemptCancel()
		if err == nil {
			return association, nil
		}
		lastErr = err
		c.metrics.UDPAssociationRescueFailure()
		c.cfg.Logger.Warn("UDP association rescue unavailable", "attempt", attempt+1, "error", err)
	}
	if lastErr == nil {
		lastErr = errors.New("UDP association rescue exhausted")
	}
	return nil, fmt.Errorf("UDP association rescue exhausted after %d attempts: %w", maxUDPReconnectAttempts, lastErr)
}

func udpReconnectBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	delay := udpReconnectInitialBackoff
	for i := 0; i < attempt && delay < udpReconnectMaximumBackoff; i++ {
		delay *= 2
	}
	if delay > udpReconnectMaximumBackoff {
		return udpReconnectMaximumBackoff
	}
	return delay
}

func waitForUDPReconnect(ctx context.Context, controlClosed <-chan struct{}, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-controlClosed:
		return errUDPControlClosed
	case <-timer.C:
		return nil
	}
}

// stopUDPAssociationLane waits for both lane workers after cancellation. The
// uplink uses a one-second read poll, so this bound prevents an old worker from
// consuming a datagram after a replacement lane has been installed while also
// keeping shutdown independent of a broken transport.
func stopUDPAssociationLane(cancel context.CancelFunc, lane *authenticatedLane, results <-chan error, completed int) {
	cancel()
	if lane != nil && lane.fc != nil {
		_ = lane.fc.Close()
	}
	deadline := time.NewTimer(udpReadPoll + 500*time.Millisecond)
	defer deadline.Stop()
	for completed < 2 {
		select {
		case <-results:
			completed++
		case <-deadline.C:
			return
		}
	}
}

// closeUDPAssociation performs the bounded half-close handshake. Other
// frames may be in flight when the SOCKS control connection closes, so a
// non-ACK worker error is recorded but does not prevent waiting for the final
// acknowledgement from the downlink worker.
func (c *Client) closeUDPAssociation(lane *authenticatedLane, flowID uint64, results <-chan error) error {
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := lane.fc.WriteContext(closeCtx, protocol.Frame{Header: protocol.Header{
		Version: protocol.Version, Type: protocol.TypeClose, Flags: protocol.FlagFin,
		SessionID: lane.sessionID, FlowID: flowID,
		Class: protocol.ClassInteractive,
	}}); err != nil {
		return err
	}
	ackDeadline := time.NewTimer(2 * time.Second)
	defer ackDeadline.Stop()
	var lastErr error
	for received := 0; received < 2; received++ {
		select {
		case err := <-results:
			if errors.Is(err, errUDPAssociationCloseAck) {
				return nil
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				lastErr = err
			}
		case <-ackDeadline.C:
			if lastErr != nil {
				return lastErr
			}
			return errors.New("UDP association close acknowledgement timeout")
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("UDP association close acknowledgement missing")
}

// udpAssociation is what an open produced: the lane, the flow it belongs to,
// and the token naming the relay behind it. The token is empty against a peer
// that did not advertise CapabilityUDPResume, and a rescue then behaves
// exactly as it did before -- a fresh relay, and a destination that sees a
// new source address.
type udpAssociation struct {
	lane   *authenticatedLane
	flowID uint64
	token  []byte
}

type udpAssociationOpenTransportError struct {
	operation string
	err       error
}

func (e *udpAssociationOpenTransportError) Error() string {
	return e.operation + ": " + e.err.Error()
}

func (e *udpAssociationOpenTransportError) Unwrap() error { return e.err }

func (c *Client) openUDPAssociation(ctx context.Context, resume []byte) (*udpAssociation, error) {
	association, err := c.openUDPAssociationMode(ctx, resume, false, false)
	if err == nil || ctx.Err() != nil {
		return association, err
	}
	var transportErr *udpAssociationOpenTransportError
	if !errors.As(err, &transportErr) {
		return nil, err
	}
	// The first failure has already retired a timed-out pooled QUIC
	// generation. AUTO uses its authenticated TCP path for this one bounded
	// retry, while later associations are free to establish a fresh QUIC pool.
	retry, retryErr := c.openUDPAssociationMode(ctx, resume, true, false)
	if retryErr != nil {
		return nil, fmt.Errorf("UDP association open failed (%v); fast retry failed: %w", err, retryErr)
	}
	return retry, nil
}

func (c *Client) openUDPAssociationMode(ctx context.Context, resume []byte, fastRetry, rescue bool) (*udpAssociation, error) {
	var lane *authenticatedLane
	var err error
	if (fastRetry || rescue) && c.cfg.Transport == TransportAuto {
		// An established association already failed. Waiting for another QUIC
		// dial -- or retrying a just-failed association on the same path -- can
		// exceed the preserved SOCKS datagram's useful lifetime, so recover this
		// flow over the warm standby transport without changing global UDP health.
		c.metrics.Fallback()
		lane, err = c.dialAuthenticatedCandidate(ctx, TransportTCP)
	} else {
		lane, err = c.chooseAuthenticatedLane(ctx)
	}
	if err != nil {
		return nil, err
	}
	flowID, err := randomFlowID()
	if err != nil {
		_ = lane.fc.Close()
		return nil, err
	}
	encoded, encodeErr := session.EncodeUDPResumeOpen(resume)
	if encodeErr != nil {
		_ = lane.fc.Close()
		return nil, encodeErr
	}
	payload := encoded
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
	association := &udpAssociation{lane: lane, flowID: flowID}
	resumed, granted, ok := session.DecodeUDPResumeGrant(response.Payload)
	if !ok {
		_ = lane.fc.Close()
		return nil, errors.New("invalid UDP association resume grant")
	}
	association.token = granted[:]
	if len(resume) > 0 && !resumed {
		// The relay was not reclaimed: it expired, or the lane that held
		// it never failed the way the server expects. The association
		// works, and the destination sees a new source address.
		c.cfg.Logger.Debug("UDP association relay not resumed", "flow", flowID)
	}
	_ = lane.outer.SetDeadline(time.Time{})
	return association, nil
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

func (s *Server) handleUDPAssociation(ctx context.Context, conn streamConn, fc *frameConn, user string, sessionID [16]byte, flowID uint64, resume []byte, resumable bool) {
	// A token this association asks to reclaim names a relay whose lane died.
	// Claiming is best effort: if the token is unknown, spent, or expired,
	// this is an ordinary open with a fresh socket, which is exactly the
	// behaviour that existed before resume did.
	var udpConn *net.UDPConn
	resumed := false
	if resumable && len(resume) > 0 {
		if held := s.udpRelays.claim(resume, user); held != nil {
			udpConn, resumed = held, true
		}
	}
	if udpConn == nil {
		listened, err := net.ListenUDP("udp", &net.UDPAddr{})
		if err != nil {
			_ = fc.Write(protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeReset, SessionID: sessionID, FlowID: flowID, Class: protocol.ClassInteractive}, Payload: session.ResetPayload(session.ResetTransport, "UDP relay unavailable")})
			return
		}
		udpConn = listened
	}

	// A resumable association is answered with the token its relay will
	// answer to next, reissued even when the resume succeeded: a token that
	// outlived its own use would let one failed lane be replayed against
	// every relay the association had after it.
	var grant [session.UDPResumeTokenSize]byte
	if resumable {
		minted, err := newUDPResumeToken()
		if err != nil {
			_ = udpConn.Close()
			_ = fc.Write(protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeReset, SessionID: sessionID, FlowID: flowID, Class: protocol.ClassInteractive}, Payload: session.ResetPayload(session.ResetTransport, "UDP relay unavailable")})
			return
		}
		grant = minted
	}

	// How this association ends decides what happens to its socket. A clean
	// dissociation or a refused open closes it; a transport failure parks it,
	// because that is the case a replacement is coming for.
	retain := false
	defer func() {
		if resumable && retain {
			s.cfg.Logger.Debug("UDP association relay retained for a replacement",
				"relay", udpConn.LocalAddr().String(), "resumed", resumed)
			s.udpRelays.retain(grant, user, udpConn)
			return
		}
		_ = udpConn.Close()
	}()

	openOK := protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeOpenOK, SessionID: sessionID, FlowID: flowID, Class: protocol.ClassInteractive}}
	if resumable {
		openOK.Payload = session.EncodeUDPResumeGrant(resumed, grant)
	}
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
				frameErr <- readErr
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
	go func() {
		buf := make([]byte, 65535)
		for {
			_ = udpConn.SetReadDeadline(time.Now().Add(udpReadPoll))
			n, addr, readErr := udpConn.ReadFromUDP(buf)
			if readErr != nil {
				if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
					if assocCtx.Err() != nil {
						packetErr <- assocCtx.Err()
						return
					}
					continue
				}
				// As on the uplink: an unreachable peer describes one
				// datagram, not this association.
				if udperr.Transient(readErr) {
					continue
				}
				packetErr <- readErr
				return
			}
			destination, err := session.DestinationFromUDPAddr(addr)
			if err != nil {
				continue
			}
			select {
			case packets <- udpDatagram{destination: destination, payload: append([]byte(nil), buf[:n]...)}:
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
		case frame := <-frames:
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
			resolveCtx, resolveCancel := context.WithTimeout(assocCtx, 10*time.Second)
			addresses, resolveErr := s.cfg.DestinationPolicy.ResolveUDPAddr(resolveCtx, destination)
			resolveCancel()
			if resolveErr != nil {
				continue
			}
			var writeErr error
			for _, address := range addresses {
				_ = udpConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, writeErr = udpConn.WriteToUDP(payload, address); writeErr == nil {
					break
				}
			}
			if writeErr != nil {
				continue
			}
			counters.up.Add(uint64(len(payload)))
			resetIdle()
		case packet := <-packets:
			payload, encodeErr := session.EncodeUDPPacket(packet.destination, packet.payload)
			if encodeErr != nil {
				continue
			}
			if writeErr := fc.WriteContext(assocCtx, protocol.Frame{Header: protocol.Header{
				Version: protocol.Version, Type: protocol.TypePacket, SessionID: sessionID,
				FlowID: flowID, Sequence: replySequence, Class: protocol.ClassInteractive,
			}, Payload: payload}); writeErr != nil {
				endErr = writeErr
				failed = true
				// The lane went, not the association. Keep the relay for
				// the replacement that is about to ask for it.
				retain = true
				goto done
			}
			replySequence++
			counters.down.Add(uint64(len(packet.payload)))
			resetIdle()
		case err := <-frameErr:
			if assocCtx.Err() != nil {
				// Service shutdown closes the transport and cancels this context
				// concurrently. The reader's EOF can win the select even though
				// the association did not fail; keep shutdown from incrementing
				// the failure counter nondeterministically.
				retain = true
				goto done
			}
			endErr = err
			failed = true
			// Same: the lane's stream ended under an association that had
			// not been dissociated, which is exactly the case a rescue
			// follows. Anything else that ends this loop -- a clean close, a
			// timeout, the relay socket itself failing, a peer sending an
			// invalid frame -- is the association ending, and its socket goes
			// with it.
			retain = true
			s.cfg.Logger.Debug("UDP relay frame reader ended", "error", err)
			goto done
		case err := <-packetErr:
			if assocCtx.Err() != nil {
				// The relay read deadline observes the same cancellation. As with
				// the frame reader, selecting its error first is still a clean
				// service shutdown.
				retain = true
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
			// The transport this association was accepted on is shutting
			// down. That is not the association ending -- a client whose
			// lane just went is about to rescue, possibly onto another
			// transport this same server still serves -- so the relay is
			// kept for it. On a full shutdown nobody claims it and the
			// store's sweeper closes it within the grace period.
			retain = true
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
	destination string
	payload     []byte
}

func notifyActivity(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}
