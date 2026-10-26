package pep

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	wancongestion "github.com/sagernet/sing-quic/congestion_queqiao"
	"github.com/sagernet/sing-quic/queqiao/internal/classifier"
	"github.com/sagernet/sing-quic/queqiao/internal/limiter"
	"github.com/sagernet/sing-quic/queqiao/internal/metrics"
	"github.com/sagernet/sing-quic/queqiao/internal/portmux"
	"github.com/sagernet/sing-quic/queqiao/internal/profile"
	"github.com/sagernet/sing-quic/queqiao/internal/protocol"
	"github.com/sagernet/sing-quic/queqiao/internal/session"
)

type userContextKey struct{}

// UserFromContext returns the authenticated username from the context.
func UserFromContext(ctx context.Context) string {
	user, _ := ctx.Value(userContextKey{}).(string)
	return user
}

// Must exceed the client's bounded lane-replacement wait so a final-ACK loss
// can still be repaired after QUIC dead-path detection and scheduler backoff.
// Tombstones retain only final sequence metadata and remain bounded by the
// configured session admission limit.
const completedSessionLinger = 90 * time.Second

type ServerConfig struct {
	// Profile names the deployment this gateway serves; see internal/profile.
	// The zero value is the supported access-link profile.
	Profile                       profile.Profile
	ListenAddr                    string
	TLSConfig                     *tls.Config
	Authenticator                 func(auth string) (user string, ok bool)
	Passwords                     []string
	ProviderID                    string
	ChunkSize                     int
	HandshakeTimeout              time.Duration
	FlowIdleTimeout               time.Duration
	FlowMaxLifetime               time.Duration
	MaxSessions                   int
	DestinationPolicy             DestinationDialer
	Congestion                    CongestionControlKind
	BrutalBytesPerSec             uint64
	AdaptiveMinBytesSec           uint64
	AdaptiveMaxBytesSec           uint64
	AggregateBytesPerSec          uint64
	InteractiveReserveBytesPerSec uint64
	// StreamReceiveWindow and ConnectionReceiveWindow override the QUIC
	// receive windows. Zero selects the defaults, which match TUIC.
	StreamReceiveWindow     uint64
	ConnectionReceiveWindow uint64
	Metrics                 *metrics.Registry
	Logger                  *slog.Logger
	// UDPOnStream keeps SOCKS UDP packets on the lane's control stream even
	// where the QUIC connection negotiated datagrams. See the client's field:
	// it is a measurement control, and both endpoints must agree for the
	// comparison to mean anything.
	UDPOnStream bool
	// HopPortCount enables the server to accept QUIC connections on multiple
	// UDP ports simultaneously. It must match the client's hop_port_count in
	// the profile. 0 and 1 both disable port hopping. Values ≥ 2 cause the
	// server to listen on that many ports derived from the provider ID and
	// route responses back through whichever port each client most recently
	// used.
	HopPortCount int
	// testLaneWriteHook is intentionally unexported and nil in production. It
	// lets package integration tests reproduce loss of a specific logical
	// frame without depending on encrypted QUIC packet layout.
	testLaneWriteHook func(protocol.Frame) error
}

type Server struct {
	cfg              ServerConfig
	semaphore        chan struct{}
	connections      chan struct{}
	sessionsMu       sync.RWMutex
	sessions         map[[16]byte]*serverFlow
	maxObservedLanes atomic.Int64
	refusals         recordLimiter
	budget           *limiter.Budget
	metrics          *metrics.Registry
}

type serverFlow struct {
	flow      *multipathFlow
	user      string
	maxLanes  int
	completed atomic.Bool
	tombstone sync.Once
	mu        sync.Mutex
}

// quicAuthState carries the immutable user established by the authentication
// handshake. flows counts sessions multiplexed on the connection.
type quicAuthState struct {
	user  string
	flows atomic.Int64
}

// shared reports whether more than one flow is using this connection.
func (a *quicAuthState) shared() bool {
	if a == nil {
		return false
	}
	return a.flows.Load() > 1
}

// serverLaneBudget is the total lanes this endpoint will admit for one flow.
// It must match the client's split in bulkLaneBudget: counting the reserved
// control lane against the bulk maximum makes the server reject and close
// every joined bulk lane, which the peer sees as an immediate EOF and retries,
// churning through lanes instead of transferring.
func serverLaneBudget(reserveControl bool) int {
	bulk, control := bulkLaneBudget(reserveControl)
	return bulk + control
}

// laneJoinAdmissionTimeout bounds the OPEN_OK write of an admitted JOIN. The
// connection handshake deadline is already cleared by then, so without its
// own bound a blocked write holds a staged lane -- counted against the
// admission ceiling, never ready, never schedulable -- for as long as the
// peer stays half-open. One path-detection budget matches the rescue-race
// window a young staged lane is protected from eviction for.
const laneJoinAdmissionTimeout = laneDeadPathDetection

var (
	// errLaneFlowClosed refuses a lane for a flow that is already gone.
	errLaneFlowClosed = errors.New("flow is closed")
	// errLaneDuplicateID refuses a lane id the flow already carries.
	errLaneDuplicateID = errors.New("duplicate lane id")
	// errLaneLimitReached is the genuine admission ceiling, the one refusal
	// a peer may legitimately retry: lanes come and go, so the answer can
	// change during the flow's life.
	errLaneLimitReached = errors.New("flow lane limit reached")
)

func (s *serverFlow) addLane(lane *mpLane) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flow.laneCount() >= s.maxLanes {
		if !s.flow.retireOldestLane(lane.control, laneDeadPathDetection) || s.flow.laneCount() >= s.maxLanes {
			return errLaneLimitReached
		}
	}
	return s.flow.addLane(lane)
}

func newServerFlow(flow *multipathFlow, user string) *serverFlow {
	return &serverFlow{
		flow:     flow,
		user:     user,
		maxLanes: serverLaneBudget(flow.reserveControlLane),
	}
}

func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.TLSConfig == nil {
		return nil, errors.New("server TLS configuration is required")
	}
	if cfg.ChunkSize <= 0 || cfg.ChunkSize > protocol.MaxPayload {
		cfg.ChunkSize = defaultChunkSize
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.FlowIdleTimeout <= 0 {
		cfg.FlowIdleTimeout = defaultFlowIdleTimeout
	}
	if cfg.FlowMaxLifetime <= 0 {
		cfg.FlowMaxLifetime = defaultFlowMaxLifetime
	}
	if cfg.FlowIdleTimeout > cfg.FlowMaxLifetime {
		return nil, errors.New("flow idle timeout cannot exceed maximum lifetime")
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 4096
	}
	if cfg.MaxSessions > maxConfiguredSessions {
		return nil, fmt.Errorf("maximum sessions must not exceed %d", maxConfiguredSessions)
	}
	if cfg.Congestion == "" {
		cfg.Congestion = defaultCongestion()
	}
	if cfg.Congestion != CongestionReno && cfg.Congestion != CongestionBBR && cfg.Congestion != CongestionBBRTUIC && cfg.Congestion != CongestionErasure && cfg.Congestion != CongestionAdaptive && cfg.Congestion != CongestionBrutal {
		return nil, fmt.Errorf("unsupported QUIC congestion controller %q", cfg.Congestion)
	}
	if cfg.Congestion == CongestionBrutal && cfg.BrutalBytesPerSec == 0 {
		return nil, errors.New("brutal congestion requires a positive per-lane byte rate")
	}
	if cfg.AdaptiveMinBytesSec == 0 {
		cfg.AdaptiveMinBytesSec = defaultAdaptiveMinBytesPerSec
	}
	if cfg.AdaptiveMaxBytesSec == 0 {
		cfg.AdaptiveMaxBytesSec = defaultAdaptiveMaxBytesPerSec
	}
	if cfg.AdaptiveMaxBytesSec < cfg.AdaptiveMinBytesSec {
		return nil, errors.New("adaptive maximum byte rate cannot be below its minimum")
	}
	if cfg.AggregateBytesPerSec == 0 && cfg.InteractiveReserveBytesPerSec != 0 {
		return nil, errors.New("interactive reserve requires an aggregate byte budget")
	}
	if cfg.AggregateBytesPerSec != 0 && cfg.InteractiveReserveBytesPerSec >= cfg.AggregateBytesPerSec {
		return nil, errors.New("interactive reserve must leave bulk capacity below the aggregate byte budget")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Metrics == nil {
		cfg.Metrics = metrics.New()
	}
	if cfg.ProviderID == "" {
		cfg.ProviderID = "queqiao"
	}
	if cfg.DestinationPolicy == nil {
		cfg.DestinationPolicy = &directDestinationPolicy{policy: DestinationPolicy{AllowPrivate: true}}
	}
	budget := limiter.New(limiter.Config{TotalBytesPerSec: cfg.AggregateBytesPerSec, ReserveBytesPerSec: cfg.InteractiveReserveBytesPerSec})
	cfg.ChunkSize = chunkSizeForBudget(cfg.ChunkSize, budget)
	server := &Server{
		cfg:         cfg,
		semaphore:   make(chan struct{}, cfg.MaxSessions),
		connections: make(chan struct{}, cfg.MaxSessions),
		sessions:    make(map[[16]byte]*serverFlow),
		budget:      budget,
		metrics:     cfg.Metrics,
	}
	return server, nil
}

// Metrics exposes aggregate counters for an optional operator endpoint.
func (s *Server) Metrics() *metrics.Registry { return s.metrics }

func (s *Server) Serve(ctx context.Context) error {
	if s.cfg.ListenAddr == "" {
		return errors.New("server listen address is required")
	}
	return s.serveQUIC(ctx)
}

func (s *Server) serveQUIC(ctx context.Context) error {
	packetConn, err := net.ListenPacket("udp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on remote QUIC address: %w", err)
	}
	return s.ServePacketConn(ctx, packetConn)
}

// ServePacketConn runs the QUIC listener on an already-bound UDP socket.
func (s *Server) ServePacketConn(ctx context.Context, packetConn net.PacketConn) error {
	if s.cfg.HopPortCount > 1 {
		// Hop sockets are bound here rather than in a caller, because only the
		// socket's own address names the port list both peers derive. A host
		// that supplies an already-bound socket still gets the full pool.
		if udpConn, isUDP := packetConn.(*net.UDPConn); isUDP {
			primaryPort := udpConn.LocalAddr().(*net.UDPAddr).Port
			ports := portmux.HopPorts(s.cfg.ProviderID, primaryPort, s.cfg.HopPortCount)
			mux, muxErr := portmux.NewServerPortMux(udpConn, ports)
			if muxErr == nil {
				s.cfg.Logger.Info("port hop listener ready",
					"primary_addr", udpConn.LocalAddr(),
					"hop_port_count", len(ports)-len(mux.SkippedPorts()),
					"hop_ports_configured", len(ports),
					"hop_ports_unavailable", mux.SkippedPorts())
				packetConn = mux
			} else {
				s.cfg.Logger.Error("failed to create port mux; serving the primary port only", "error", muxErr)
			}
		} else {
			s.cfg.Logger.Warn("cannot enable port hop: connection is not a UDP socket")
		}
	}
	listener, err := quic.Listen(packetConn, s.cfg.TLSConfig, quicServerConfig(
		flowWindows{stream: s.cfg.StreamReceiveWindow, connection: s.cfg.ConnectionReceiveWindow}))
	if err != nil {
		_ = packetConn.Close()
		return fmt.Errorf("create QUIC listener: %w", err)
	}
	defer listener.Close()
	defer packetConn.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	s.cfg.Logger.Info("remote QUIC listener ready", "address", listener.Addr().String())
	var wg sync.WaitGroup
	for {
		conn, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) {
				wg.Wait()
				return nil
			}
			return fmt.Errorf("accept QUIC lane: %w", acceptErr)
		}
		if !s.admitConnection() {
			_ = conn.CloseWithError(0x100, "server connection limit reached")
			s.cfg.Logger.Warn("remote QUIC connection limit reached")
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.releaseConnection()
			s.handleQUIC(ctx, conn)
		}()
	}
}

func (s *Server) admitConnection() bool {
	select {
	case s.connections <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseConnection() { <-s.connections }

func (s *Server) authenticateConn(ctx context.Context, conn *quic.Conn, controller wancongestion.TelemetryProvider) (string, error) {
	authStream, err := acceptQUICStream(ctx, conn, controller)
	if err != nil {
		return "", err
	}
	defer authStream.Close()
	_ = authStream.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	fc := newFrameConn(authStream)
	authFrame, err := fc.Read()
	if err != nil {
		return "", err
	}
	if authFrame.Header.Type != protocol.TypeAuth {
		return "", fmt.Errorf("unexpected frame type %d on auth stream", authFrame.Header.Type)
	}
	authData := string(authFrame.Payload)
	var user string
	var ok bool
	if s.cfg.Authenticator != nil {
		user, ok = s.cfg.Authenticator(authData)
	} else {
		for _, pass := range s.cfg.Passwords {
			if pass == authData {
				user = authData
				ok = true
				break
			}
		}
	}
	if !ok {
		_ = fc.Write(protocol.Frame{
			Header: protocol.Header{
				Version: protocol.Version,
				Type:    protocol.TypeReset,
			},
			Payload: session.ResetPayload(session.ResetAuthentication, "authentication failed"),
		})
		return "", errors.New("authentication failed")
	}
	if err := fc.Write(protocol.Frame{
		Header: protocol.Header{
			Version: protocol.Version,
			Type:    protocol.TypeAuthOK,
		},
	}); err != nil {
		return "", err
	}
	return user, nil
}

func (s *Server) handleQUIC(ctx context.Context, conn *quic.Conn) {
	var wg sync.WaitGroup
	defer wg.Wait()
	defer conn.CloseWithError(0, "queqiao session complete")
	controller := configureQUICController(conn, congestionConfig{
		kind: s.cfg.Congestion, brutalBytesPerSecond: s.cfg.BrutalBytesPerSec,
		adaptiveMinBytesPerSec: s.cfg.AdaptiveMinBytesSec, adaptiveMaxBytesPerSec: s.cfg.AdaptiveMaxBytesSec,
	})

	user, err := s.authenticateConn(ctx, conn, controller)
	if err != nil {
		s.cfg.Logger.Debug("QUIC client authentication failed", "error", err)
		_ = conn.CloseWithError(0x101, "auth failed")
		return
	}

	auth := &quicAuthState{user: user}
	dispatch := func(lane streamConn) bool {
		select {
		case s.semaphore <- struct{}{}:
			wg.Add(1)
			go func(lane streamConn) {
				defer wg.Done()
				defer func() { <-s.semaphore }()
				s.handleSession(ctx, lane, user, auth)
			}(lane)
			return true
		default:
			_ = lane.Close()
			s.cfg.Logger.Warn("remote session limit reached")
			return false
		}
	}
	for {
		stream, err := acceptQUICStream(ctx, conn, controller)
		if err != nil {
			if ctx.Err() == nil {
				s.cfg.Logger.Debug("accept QUIC stream failed", "error", err)
			}
			return
		}
		dispatch(stream)
	}
}

func (s *Server) handleSession(ctx context.Context, conn streamConn, user string, auth *quicAuthState) {
	ctx = context.WithValue(ctx, userContextKey{}, user)
	if streamConn, isQUIC := conn.(*quicStreamConn); isQUIC && streamConn.conn != nil {
		ctx = WithPeerAddr(ctx, streamConn.conn.RemoteAddr())
	}
	defer conn.Close()
	if auth != nil {
		auth.flows.Add(1)
		defer auth.flows.Add(-1)
	}
	sessionStarted := time.Now()
	_ = conn.SetDeadline(time.Now().Add(handshakeBound(conn, s.cfg.HandshakeTimeout)))
	fc := newFrameConn(conn)
	fc.setPacketsOnStream(s.cfg.UDPOnStream)
	open, err := fc.Read()
	if err != nil {
		s.cfg.Logger.Debug("read authenticated stream open", "error", err)
		return
	}
	if open.Header.Type == protocol.TypeProbe {
		s.handlePathProbe(fc, open)
		return
	}
	if open.Header.Type == protocol.TypeJoin {
		if session.IsZeroSessionID(open.Header.SessionID) || open.Header.FlowID == 0 || open.Header.Sequence != 0 || open.Header.Flags&^protocol.FlagReserveControl != 0 || len(open.Payload) != 8 {
			_ = fc.Write(protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeReset, SessionID: open.Header.SessionID, FlowID: open.Header.FlowID, Class: protocol.ClassBulk}, Payload: session.ResetPayload(session.ResetProtocol, "invalid lane join")})
			return
		}
		laneID := binary.BigEndian.Uint64(open.Payload)
		if laneID == 0 {
			_ = fc.Write(protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeReset, SessionID: open.Header.SessionID, FlowID: open.Header.FlowID, Class: protocol.ClassBulk}, Payload: session.ResetPayload(session.ResetProtocol, "invalid lane join")})
			return
		}
		s.handleLaneJoinOpen(ctx, conn, fc, user, open.Header.SessionID, laneID, open)
		return
	}
	sessionID := open.Header.SessionID
	laneID := uint64(0)
	if open.Header.Type != protocol.TypeOpen || session.IsZeroSessionID(sessionID) || open.Header.FlowID == 0 || open.Header.Sequence != 0 {
		_ = fc.Write(protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeReset, SessionID: sessionID, FlowID: open.Header.FlowID, Class: protocol.ClassNew}, Payload: session.ResetPayload(session.ResetProtocol, "invalid flow open")})
		return
	}
	if session.IsUDPAssociation(open.Payload) {
		s.handleUDPAssociation(ctx, conn, fc, user, sessionID, open.Header.FlowID)
		return
	}
	destination, err := session.DecodeDestination(open.Payload)
	if err != nil {
		_ = fc.Write(protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeReset, SessionID: sessionID, FlowID: open.Header.FlowID, Class: protocol.ClassNew}, Payload: session.ResetPayload(session.ResetDestination, "destination unavailable")})
		return
	}
	destinationDialStarted := time.Now()
	destinationConn, err := s.cfg.DestinationPolicy.DialContext(ctx, user, destination)
	if err != nil {
		_ = fc.Write(protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeReset, SessionID: sessionID, FlowID: open.Header.FlowID, Class: protocol.ClassNew}, Payload: session.ResetPayload(session.ResetDestination, "destination unavailable")})
		s.cfg.Logger.Debug("destination dial failed", "error", err)
		_ = destinationConn
		return
	}
	s.cfg.Logger.Debug("remote flow opened", "transport", transportKindForConn(conn), "user", user, "open_duration", destinationDialStarted.Sub(sessionStarted), "destination_dial_duration", time.Since(destinationDialStarted), "total_duration", time.Since(sessionStarted))
	defer destinationConn.Close()
	flow := newMultipathFlow(ctx, destinationConn, sessionID, open.Header.FlowID, s.cfg.ChunkSize, protocol.FlagAckDown, protocol.FlagAckUp, s.budget, s.metrics, s.cfg.Logger)
	flow.classifier = classifier.New(s.classifierConfig())
	// Wire version 1 requires range acknowledgements on both endpoints.
	flow.ackRanges.Store(true)
	flow.idleTimeout = s.cfg.FlowIdleTimeout
	flow.maxLifetime = s.cfg.FlowMaxLifetime
	flow.reserveControlLane = open.Header.Flags&protocol.FlagReserveControl != 0
	flow.controlLaneShared = auth.shared
	initialKind := transportKindForConn(conn)
	serverSession := newServerFlow(flow, user)
	if err := serverSession.addLane(&mpLane{
		id: laneID, kind: initialKind, fc: fc, writeHook: s.cfg.testLaneWriteHook,
		control: flow.reserveControlLane && initialKind == TransportQUIC,
	}); err != nil {
		flow.closeAll()
		return
	}
	s.observeLanes(serverSession.flow.laneCount())
	if !s.registerSession(sessionID, serverSession) {
		_ = fc.Write(protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeReset, SessionID: sessionID, FlowID: open.Header.FlowID, Class: protocol.ClassNew}, Payload: session.ResetPayload(session.ResetFlowLimit, "session already exists")})
		flow.closeAll()
		return
	}
	registered := true
	go s.watchFlowCompletion(ctx, sessionID, serverSession)
	defer func() {
		if registered {
			s.cfg.Logger.Debug("session released with its flow", "lanes", serverSession.flow.laneCount())
			s.unregisterSession(sessionID, serverSession)
		}
	}()
	if err := fc.Write(protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeOpenOK, SessionID: sessionID, FlowID: open.Header.FlowID, Class: protocol.ClassNew}}); err != nil {
		flow.closeAll()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	s.metrics.FlowStarted()
	stats, err := flow.run(ctx)
	// A peer may close the transport immediately after receiving the final
	// bytes, racing the server's final-ACK bookkeeping. If both directions
	// have observed FIN sequences, the logical flow is complete even when the
	// runner reports the late socket EOF as an error; retain the same bounded
	// tombstone so a replacement lane can replay the final ACK. Do not retain
	// one-sided or context-canceled flows.
	flowComplete := err == nil || (ctx.Err() == nil && serverSession.flow.finSent.Load() && serverSession.flow.remoteFinSeen.Load())
	if !flowComplete && ctx.Err() == nil && serverSession.flow.remoteFinSeen.Load() && expectedDestinationCloseError(err) {
		flowComplete = true
	}
	s.metrics.FlowFinished(stats.BytesRead, stats.BytesSent, !flowComplete && err != nil && !errors.Is(err, context.Canceled))
	if flowComplete {
		// Keep a bounded tombstone long enough for a client that lost the
		// final cumulative ACK to authenticate a replacement lane and finish
		// its local close handshake. No destination connection or payload is
		// retained; only the flow's final sequence metadata remains.
		s.retainCompletedSession(sessionID, serverSession)
		registered = false
	}
	codedFrames, streamFrames := flow.dataSubstrates()
	substrate, hasCoded := flow.codedSubstrate()
	logFields := []any{
		"session_id", fmt.Sprintf("%x", sessionID), "flow_id", flow.flowID,
		"transport", transportKindForConn(conn), "bytes_from_client", stats.BytesRead, "bytes_to_client", stats.BytesSent,
		"duration", stats.Ended.Sub(stats.Started), "lane_bytes", stats.LaneBytes,
		// Where the payload went. The server is the sender for a download, so
		// this is the split that decides what a download costs.
		"data_coded", codedFrames, "data_stream", streamFrames,
		"coded_substrate", codedSubstrateFields(substrate, hasCoded),
		"class", classifier.Class(flow.class.Load()),
	}
	logFields = append(logFields, codedSubstrateLogFields(substrate, hasCoded)...)
	logFields = append(logFields, flow.replacementLogFields()...)
	if !flowComplete && err != nil && !errors.Is(err, context.Canceled) {
		s.cfg.Logger.Warn("remote flow ended with error", append(logFields, "error", err)...)
		return
	}
	s.cfg.Logger.Info("remote flow complete", logFields...)
}

const (
	maxPathProbeFrames = protocol.MaxProbeFrames
	maxPathProbeBytes  = protocol.MaxProbeBytes
)

// handlePathProbe accepts only a small, destination-free sequence and reflects
// each validated frame exactly once. The equal-size authenticated echo cannot
// amplify traffic or name a destination, and it gives this endpoint's own
// congestion controller outbound packets to measure. That is the only sound
// source for its sending direction; reverse-direction arrivals cannot reveal
// which losses the peer caused by its offered rate.
func (s *Server) handlePathProbe(fc *frameConn, first protocol.Frame) {
	frames, bytes := 0, 0
	frame := first
	sessionID := first.Header.SessionID
	for {
		if frame.Header.Type != protocol.TypeProbe || session.IsZeroSessionID(frame.Header.SessionID) ||
			frame.Header.SessionID != sessionID ||
			frame.Header.FlowID != 0 || frame.Header.Sequence != uint64(frames) || frame.Header.Flags != 0 ||
			frame.Header.Class != protocol.ClassNew || len(frame.Payload) == 0 || len(frame.Payload) > protocol.MaxProbePayload ||
			bytes+len(frame.Payload) > maxPathProbeBytes {
			return
		}
		frames++
		bytes += len(frame.Payload)
		if err := fc.Write(frame); err != nil {
			return
		}
		if frames >= maxPathProbeFrames || bytes >= maxPathProbeBytes {
			return
		}
		next, err := fc.Read()
		if err != nil {
			return
		}
		frame = next
	}
}

// watchFlowCompletion closes a correctness gap between the application FIN
// exchange and the flow runner's final goroutine return. Both direction FIN
// sequences prove that no additional payload can be delivered, so retaining
// a tombstone at that point lets a replacement lane replay the final ACK even
// if the peer has already closed its socket and the runner is waiting for a
// late duplicate ACK.
func (s *Server) watchFlowCompletion(ctx context.Context, sessionID [16]byte, serverSession *serverFlow) {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if ctx.Err() == nil && serverSession.flow.finSent.Load() && serverSession.flow.remoteFinSeen.Load() {
				s.retainCompletedSession(sessionID, serverSession)
				// Both FINs are an application-level proof that no additional
				// payload can be delivered in either direction. Tear down the
				// physical lanes now; otherwise sendInner can wait forever for a
				// final ACK lost in the last-lane close race and receiveInner can
				// wait forever for another frame. The tombstone above preserves
				// final-ACK metadata for bounded replay.
				serverSession.flow.closeAll()
				return
			}
		case <-serverSession.flow.doneChan():
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) retainCompletedSession(sessionID [16]byte, serverSession *serverFlow) {
	serverSession.tombstone.Do(func() {
		serverSession.completed.Store(true)
		time.AfterFunc(completedSessionLinger, func() {
			s.cfg.Logger.Debug("session tombstone expired")
			s.unregisterSession(sessionID, serverSession)
		})
	})
}

// refuseLaneJoin answers a lane join with a reset, and says so where an
// operator will see it.
func (s *Server) refuseLaneJoin(fc *frameConn, sessionID [16]byte, flowID, laneID uint64, reason metrics.LaneJoinRefusal, code session.ResetCode, message string) {
	s.metrics.LaneJoinRefused(reason)
	if write, suppressed, total := s.refusals.due(reason, time.Now()); write {
		level := slog.LevelInfo
		if reason == metrics.LaneJoinPrincipalMismatch || reason == metrics.LaneJoinFlowMismatch {
			level = slog.LevelWarn
		}
		s.cfg.Logger.LogAttrs(context.Background(), level, "lane join refused",
			slog.String("reason", reason.String()),
			slog.Uint64("lane", laneID),
			slog.Uint64("flow_id", flowID),
			slog.Uint64("suppressed", suppressed),
			slog.Uint64("total", total))
	}
	_ = fc.Write(protocol.Frame{Header: protocol.Header{
		Version: protocol.Version, Type: protocol.TypeReset, SessionID: sessionID,
		FlowID: flowID, Class: protocol.ClassBulk,
	}, Payload: session.ResetPayload(code, message)})
}

// handleLaneJoinOpen runs only after authentication and exact JOIN validation.
func (s *Server) handleLaneJoinOpen(ctx context.Context, conn streamConn, fc *frameConn, user string, sessionID [16]byte, laneID uint64, open protocol.Frame) {
	if session.IsZeroSessionID(sessionID) || laneID == 0 || open.Header.FlowID == 0 {
		s.refuseLaneJoin(fc, sessionID, open.Header.FlowID, laneID, metrics.LaneJoinInvalidIdentity, session.ResetProtocol, "invalid lane join identity")
		return
	}
	serverSession := s.lookupSession(sessionID)
	switch {
	case serverSession == nil:
		s.refuseLaneJoin(fc, sessionID, open.Header.FlowID, laneID, metrics.LaneJoinUnknownSession, session.ResetProtocol, "unknown session")
		return
	case serverSession.flow.flowID != open.Header.FlowID:
		s.refuseLaneJoin(fc, sessionID, open.Header.FlowID, laneID, metrics.LaneJoinFlowMismatch, session.ResetProtocol, "unknown session")
		return
	case serverSession.user != user:
		s.refuseLaneJoin(fc, sessionID, open.Header.FlowID, laneID, metrics.LaneJoinPrincipalMismatch, session.ResetProtocol, "unknown session")
		return
	}
	if !serverSession.completed.Load() && serverSession.flow.extendReplacementOutage(time.Now(), laneReplacementWait) {
		s.metrics.LaneGraceExtended()
		s.cfg.Logger.Debug("lane replacement grace extended by rescue join", "lane", laneID, "flow_id", open.Header.FlowID)
	}
	kind := transportKindForConn(conn)
	controlReplacement := open.Header.Flags&protocol.FlagReserveControl != 0
	if controlReplacement && (!serverSession.flow.reserveControlLane || kind != TransportQUIC) {
		s.refuseLaneJoin(fc, sessionID, open.Header.FlowID, laneID, metrics.LaneJoinInvalidControlReplacement, session.ResetProtocol, "invalid control lane replacement")
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if serverSession.completed.Load() {
		s.cfg.Logger.Debug("lane join reached a completed session", "lane", laneID)
		if err := fc.Write(protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeOpenOK, SessionID: sessionID, FlowID: open.Header.FlowID, Class: protocol.ClassBulk}}); err != nil {
			return
		}
		_ = fc.Write(protocol.Frame{Header: protocol.Header{
			Version: protocol.Version, Type: protocol.TypeAck, Flags: protocol.FlagAckFinal | serverSession.flow.recvAckFlag,
			SessionID: sessionID, FlowID: open.Header.FlowID, Sequence: serverSession.flow.remoteFinSequence.Load(),
			Class: protocol.ClassBulk,
		}})
		if serverSession.flow.finSent.Load() {
			flags := uint16(protocol.FlagFin)
			if serverSession.flow.localAbortSent.Load() {
				flags |= protocol.FlagCloseAbort
			}
			_ = fc.Write(protocol.Frame{Header: protocol.Header{
				Version: protocol.Version, Type: protocol.TypeClose, Flags: flags,
				SessionID: sessionID, FlowID: open.Header.FlowID, Sequence: serverSession.flow.finSequence.Load(),
				Class: protocol.ClassBulk,
			}})
		}
		return
	}
	replacement := &mpLane{
		id: laneID, kind: kind, fc: fc, writeHook: s.cfg.testLaneWriteHook,
		control: controlReplacement, staged: true,
	}
	if err := serverSession.addLane(replacement); err != nil {
		s.cfg.Logger.Debug("lane join admission refused", "lane", laneID, "error", err)
		switch {
		case errors.Is(err, errLaneFlowClosed), errors.Is(err, errLaneDuplicateID):
			s.refuseLaneJoin(fc, sessionID, open.Header.FlowID, laneID, metrics.LaneJoinUnknownSession, session.ResetProtocol, "unknown session")
		default:
			s.refuseLaneJoin(fc, sessionID, open.Header.FlowID, laneID, metrics.LaneJoinLaneUnavailable, session.ResetFlowLimit, "lane unavailable")
		}
		return
	}
	openOK := protocol.Frame{Header: protocol.Header{Version: protocol.Version, Type: protocol.TypeOpenOK, SessionID: sessionID, FlowID: open.Header.FlowID, Class: protocol.ClassBulk}}
	writeCtx, cancelWrite := context.WithTimeout(ctx, laneJoinAdmissionTimeout)
	writeErr := fc.WriteContext(writeCtx, openOK)
	cancelWrite()
	if writeErr != nil {
		serverSession.flow.removeLane(replacement)
		return
	}
	if err := serverSession.flow.activateLane(replacement); err != nil {
		serverSession.flow.removeLane(replacement)
		return
	}
	s.cfg.Logger.Debug("lane joined", "lane", laneID, "transport", kind, "control", controlReplacement, "lanes", serverSession.flow.laneCount())
	s.observeLanes(serverSession.flow.laneCount())
	if serverSession.flow.remoteFinSeen.Load() {
		_ = fc.Write(protocol.Frame{Header: protocol.Header{
			Version: protocol.Version, Type: protocol.TypeAck,
			Flags:     protocol.FlagAckFinal | serverSession.flow.recvAckFlag,
			SessionID: sessionID, FlowID: open.Header.FlowID,
			Sequence: serverSession.flow.remoteFinSequence.Load(), Class: protocol.ClassBulk,
		}})
	}
	if serverSession.flow.finSent.Load() {
		flags := uint16(protocol.FlagFin)
		if serverSession.flow.localAbortSent.Load() {
			flags |= protocol.FlagCloseAbort
		}
		_ = fc.Write(protocol.Frame{Header: protocol.Header{
			Version: protocol.Version, Type: protocol.TypeClose, Flags: flags,
			SessionID: sessionID, FlowID: open.Header.FlowID,
			Sequence: serverSession.flow.finSequence.Load(), Class: protocol.ClassBulk,
		}})
	}
	select {
	case <-serverSession.flow.doneChan():
	case <-ctx.Done():
	}
}

func (s *Server) registerSession(id [16]byte, flow *serverFlow) bool {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if len(s.sessions) >= s.cfg.MaxSessions {
		return false
	}
	if _, exists := s.sessions[id]; exists {
		return false
	}
	s.sessions[id] = flow
	return true
}

func (s *Server) lookupSession(id [16]byte) *serverFlow {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	return s.sessions[id]
}

func (s *Server) unregisterSession(id [16]byte, flow *serverFlow) {
	s.sessionsMu.Lock()
	if s.sessions[id] == flow {
		delete(s.sessions, id)
	}
	s.sessionsMu.Unlock()
}

func (s *Server) observeLanes(count int) {
	for {
		old := s.maxObservedLanes.Load()
		if int64(count) <= old || s.maxObservedLanes.CompareAndSwap(old, int64(count)) {
			return
		}
	}
}

// MaxObservedLanes reports the largest number of lanes attached to any flow
// since this server instance started. It is safe for benchmark instrumentation
// and does not expose session IDs or destination metadata.
func (s *Server) MaxObservedLanes() int { return int(s.maxObservedLanes.Load()) }

func transportKindForConn(conn streamConn) TransportKind {
	if _, ok := conn.(*quicStreamConn); ok {
		return TransportQUIC
	}
	return TransportTCP
}

// classifierConfig is the gateway's flow-classification policy.
func (s *Server) classifierConfig() classifier.Config {
	return classifier.Config{}
}

func (s *Server) Close() error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	for _, flow := range s.sessions {
		if flow.flow != nil {
			flow.flow.closeAll()
		}
	}
	return nil
}
