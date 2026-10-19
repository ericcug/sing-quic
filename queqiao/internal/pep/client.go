package pep

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/quic-go"
	wancongestion "github.com/sagernet/sing-quic/congestion_queqiao"
	"github.com/sagernet/sing-quic/queqiao/internal/classifier"
	"github.com/sagernet/sing-quic/queqiao/internal/limiter"
	"github.com/sagernet/sing-quic/queqiao/internal/memlimit"
	"github.com/sagernet/sing-quic/queqiao/internal/metrics"
	"github.com/sagernet/sing-quic/queqiao/internal/portmux"
	"github.com/sagernet/sing-quic/queqiao/internal/profile"
	"github.com/sagernet/sing-quic/queqiao/internal/protocol"
	"github.com/sagernet/sing-quic/queqiao/internal/session"
	N "github.com/sagernet/sing/common/network"
)

// A peer that accepts a replacement stream and immediately closes it must not
// cause an endless replacement storm while the application waits for a final
// FIN. Recovery is deliberately finite; the logical flow then fails closed
// and the caller can retry.
const (
	maxTCPFallbackLanes      = 16
	defaultClientMaxSessions = 2048
	defaultMaxPendingOpens   = 256
	flowOpenRetryBaseDelay   = 500 * time.Millisecond

	maxLaneRecoveryAttempts = 8
	laneRecoveryResetAfter  = 5 * time.Minute
	// laneJoinCapacityTCPCommit is how many consecutive capacity answers a
	// recovery path takes before it stops believing the answer is transient.
	// One or two in a row are the ordinary losers of a rescue race; at three
	// the likelier reading is an admission slot wedged on the peer, and the
	// AUTO TCP commit -- deliberately suppressed for a fresh answer, since a
	// QUIC sibling may already hold the lane -- becomes the flow's escape.
	laneJoinCapacityTCPCommit = 3
	// A rejected speculative lane must not be reopened on every scheduler tick.
	// The backoff is intentionally shorter than a normal bulk request timeout,
	// but long enough to collect a fresh throughput/RTT sample on the surviving
	// control lane before trying another independent QUIC path.
	minLaneProbeBackoff  = 10 * time.Second
	maxLaneProbeBackoff  = 60 * time.Second
	maxLaneProbeAttempts = 4
	// laneDecisionInterval spaces the lane probe's samples. It bounds how fast
	// the search can converge: a baseline costs two decisions and judging a
	// probed lane costs three more, so a flow reaches its second bulk lane
	// about five intervals after it is classified as bulk. Shorter intervals
	// make each goodput sample noisier -- at a 200ms RTT, 500ms is roughly two
	// round trips of evidence -- and the probe's bias against striping is what
	// keeps that noise from producing false positives.
	laneDecisionInterval = 500 * time.Millisecond
	// Start the authenticated join slightly before the classifier's final bulk
	// transition. The lane is attached but carries no NEW/interactive DATA, so
	// this only overlaps its lossy QUIC handshake with the tail of classification.
	bulkLanePrewarmBytes = 64 * 1024
	bulkLanePrewarmAge   = 500 * time.Millisecond
	bulkLaneAsymmetry    = 8
)

type ClientConfig struct {
	RemoteAddr   string
	LocalAddress string
	// SocketControl is invoked after an outer socket is created and before it
	// is bound or connected. Mobile VPN clients use it to exempt Queqiao's own
	// TCP and UDP sockets from the virtual interface. A failure aborts the dial;
	// silently continuing would route the tunnel through itself.
	SocketControl func(network, address string, conn syscall.RawConn) error
	// Dialer, when set, establishes each outer connection through the host.
	// The host then resolves the endpoint and applies its own routing, which
	// is what makes a detour, a domain resolver and an address binding apply
	// to this outbound as they do to any other.
	Dialer     N.Dialer
	TLSConfig  *tls.Config
	Password   string
	ProviderID string
	// Profile names the deployment this client is running in, and carries the
	// policy that differs between deployments. The zero value is the supported
	// access-link profile, so a caller that does not choose gets the behaviour
	// the published measurements describe.
	Profile          profile.Profile
	ChunkSize        int
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	FlowIdleTimeout  time.Duration
	FlowMaxLifetime  time.Duration
	MaxSessions      int
	// SessionLimit optionally shares admission across several clients in one
	// process. Nil gives this client its own MaxSessions-sized limit.
	SessionLimit *SessionLimit
	// Budget optionally shares the aggregate byte budget across several
	// clients in one process. Nil derives a private budget from
	// AggregateBytesPerSec, which paces this client alone; a multi-provider
	// process must share one budget or it offers the configured total once
	// per provider.
	Budget *limiter.Budget
	// MaxPendingOpens bounds flows that are still establishing their remote
	// transport. Keeping this separate from MaxSessions prevents a failed
	// endpoint and its retries from occupying every healthy-flow slot.
	MaxPendingOpens int
	Transport       TransportKind
	// EnableQUICPool keeps one persistent QUIC connection for initial and
	// control streams, and is what makes opening a flow cost nothing.
	EnableQUICPool bool
	// WaitForOpenAcknowledgement makes a flow wait for OPEN_OK before telling
	// the application its connection is up. It is off by default, so a flow on
	// a connection that is already established costs no round trips at all.
	WaitForOpenAcknowledgement bool
	// UDPOnStream keeps SOCKS UDP packets on the lane's control stream even
	// where the QUIC connection negotiated datagrams. It is the control for
	// measuring the datagram substrate against the one it replaced, and both
	// endpoints must be set the same way for the comparison to mean anything.
	UDPOnStream                   bool
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
	// Maximum windows disable quic-go's otherwise large receive-window growth.
	// Zero keeps the high-throughput defaults. Resource-constrained clients set
	// initial and maximum to the same bounded values.
	MaxStreamReceiveWindow     uint64
	MaxConnectionReceiveWindow uint64
	MaxIncomingStreams         int64
	// MemoryLimits is required by resource-constrained clients. Nil retains
	// the throughput-oriented defaults used by servers and desktop clients.
	MemoryLimits        *MemoryLimits
	Metrics             *metrics.Registry
	UDPFailureThreshold int
	UDPCooldown         time.Duration
	// HopPortCount enables reactive UDP port hopping to evade per-port GFW
	// blocking. 0 and 1 both mean disabled. Values ≥ 2 cause the client to
	// maintain a pool of that many ports derived from the provider ID and hop
	// reactively when sustained zero-receive loss is detected.
	HopPortCount int
	Logger       *slog.Logger
}

type Client struct {
	cfg           ClientConfig
	udpHealth     *udpHealth
	budget        *limiter.Budget
	sessionLimit  *SessionLimit
	sendMemory    *memlimit.Budget
	receiveMemory *memlimit.Budget
	memoryLimits  flowMemoryLimits
	metrics       *metrics.Registry

	// One QUIC generation can carry many independent PEP streams. A generation
	// is replaced as a unit: all callers wait on the same in-flight dial, so a
	// dead shared connection causes one handshake rather than one handshake per
	// affected flow. The dial has a client lifetime of its own and is not
	// cancelled merely because the first flow waiting for it goes away.
	quicMu         sync.Mutex
	quicGeneration *controlQUICGeneration
	quicDial       *controlQUICDial
	quicEpoch      uint64
	// transientUDPLogNS rate-limits an otherwise synchronized burst of local
	// route errors while still counting every suppressed send in metrics.
	transientUDPLogNS atomic.Int64
	startOnce         sync.Once
	// hopWalk is the client-wide hop port selection state, built lazily on
	// the first hop-enabled dial so all dials share one walk.
	hopWalkOnce sync.Once
	hopWalk     *portmux.HopWalk
	// openFlowForTest stands in for one flow-open attempt, so the retry policy
	// can be tested without a network that loses things on demand.
	openFlowForTest func() (*openedFlow, error)
	// flowOpenRetryDelayForTest makes retry timing deterministic without
	// weakening the production jitter shared by concurrent callers.
	flowOpenRetryDelayForTest func(failedAttempt int) time.Duration
	// dialPipelinedFlowForTest isolates the cold-flow transport race from the
	// network in state-machine tests.
	dialPipelinedFlowForTest func(context.Context, TransportKind, []byte) (*openedFlow, error)
	// dialAuthenticatedLaneForTest isolates the pooled transport race. The
	// production path still goes through dialAuthenticatedLane; tests can make
	// TCP ready before QUIC without relying on scheduler timing or live loss.
	dialAuthenticatedLaneForTest func(context.Context, TransportKind) (*authenticatedLane, error)
	// disableStallWatchdogForTest keeps the flow stall watchdog off, so tests
	// that pin exact dial counts see only the recovery they injected, not
	// rescue rounds the watchdog starts on a slow runner.
	disableStallWatchdogForTest bool

	// quicPoolActive counts flows currently sharing the pooled control
	// connection. A bulk flow only needs to move off it when another flow
	// would otherwise queue behind its congestion window.
	quicPoolActive atomic.Int64
	// bulkMu protects a bounded set of pre-authenticated secondary QUIC
	// connections used only for fast lane joins. Keeping them separate from
	// the control pool preserves the control lane's congestion state while
	// avoiding a fresh QUIC handshake at the bulk-promotion boundary.
	//
	// Each connection carries at most one lane at a time. Multiplexing several
	// lanes of one flow onto a single connection would give them one 4-tuple
	// and one congestion controller, which is what a single TUIC connection
	// already provides: measured on a path that polices per source address,
	// striping over a shared connection produced no gain at all. A connection
	// is retained after its lane is released so a later flow still skips the
	// handshake.
	bulkMu    sync.Mutex
	bulkConns []*bulkConn

	// pendingOpens admits only bounded remote setup work. It is deliberately
	// non-blocking: callers beyond the bound are rejected promptly, release
	// their total-session slot, and leave capacity for established flows.
	pendingOpens chan struct{}
}

// SessionLimit bounds concurrent local SOCKS sessions across one or more
// clients. Admission is deliberately non-blocking so an overloaded listener
// can reject promptly instead of accumulating unauthenticated local sockets.
//
// A limit may hold a private reservation as well as a share of a pool common
// to every client. The reservation is what keeps a quiet provider able to
// admit new flows while a busy sibling holds most of the common pool: a
// failover target which cannot accept a session is not a failover target.
type SessionLimit struct {
	reserved chan struct{}
	shared   chan struct{}
}

// sessionSlot returns one admitted session to the pool it came from.
type sessionSlot struct {
	pool chan struct{}
}

func (s sessionSlot) release() {
	if s.pool != nil {
		<-s.pool
	}
}

func NewSessionLimit(max int) (*SessionLimit, error) {
	if max < 1 || max > maxConfiguredSessions {
		return nil, fmt.Errorf("maximum sessions must be between 1 and %d", maxConfiguredSessions)
	}
	return &SessionLimit{shared: make(chan struct{}, max)}, nil
}

// NewSharedSessionLimits divides max across clients so their combined
// admission never exceeds max while each client keeps a private reservation.
// Half the budget is reserved in equal shares and half stays common, so an
// idle provider can still burst into capacity its siblings are not using. When
// max is too small to reserve a slot per client the whole budget stays common.
func NewSharedSessionLimits(max, clients int) ([]*SessionLimit, error) {
	if clients < 1 {
		return nil, errors.New("shared session limits require at least one client")
	}
	if max < 1 || max > maxConfiguredSessions {
		return nil, fmt.Errorf("maximum sessions must be between 1 and %d", maxConfiguredSessions)
	}
	reserve := max / (2 * clients)
	shared := make(chan struct{}, max-reserve*clients)
	limits := make([]*SessionLimit, clients)
	for i := range limits {
		limits[i] = &SessionLimit{shared: shared}
		if reserve > 0 {
			limits[i].reserved = make(chan struct{}, reserve)
		}
	}
	return limits, nil
}

// Reserved reports the slots this limit holds for its own client alone.
func (l *SessionLimit) Reserved() int {
	if l == nil {
		return 0
	}
	return cap(l.reserved)
}

// acquire takes the private reservation first so a client's own capacity is
// never spent on a sibling. A nil limit admits: callers which never configured
// one are unlimited rather than dead.
func (l *SessionLimit) acquire() (sessionSlot, bool) {
	if l == nil {
		return sessionSlot{}, true
	}
	if l.reserved != nil {
		select {
		case l.reserved <- struct{}{}:
			return sessionSlot{pool: l.reserved}, true
		default:
		}
	}
	select {
	case l.shared <- struct{}{}:
		return sessionSlot{pool: l.shared}, true
	default:
		return sessionSlot{}, false
	}
}

// bulkConn is one pre-authenticated secondary QUIC connection reserved for
// bulk lane joins.
type bulkConn struct {
	conn       *quic.Conn
	packet     net.PacketConn
	controller wancongestion.TelemetryProvider
	busy       bool
	idleTimer  *time.Timer
}

// controlQUICGeneration owns exactly one shared connection and the packet
// socket beneath it. Keeping ownership in one object makes generation checks
// precise: a late failure from an old stream can retire its own generation but
// can never close the healthy generation which replaced it.
type controlQUICGeneration struct {
	id         uint64
	conn       *quic.Conn
	packet     net.PacketConn
	controller wancongestion.TelemetryProvider
	closeOnce  sync.Once
}

func (g *controlQUICGeneration) close(reason string) {
	if g == nil {
		return
	}
	g.closeOnce.Do(func() {
		if g.conn != nil {
			_ = g.conn.CloseWithError(0, reason)
		}
		if g.packet != nil {
			_ = g.packet.Close()
		}
	})
}

// controlQUICDial is the singleflight state for one prospective generation.
// done publishes generation and err to every waiter.
type controlQUICDial struct {
	epoch      uint64
	done       chan struct{}
	cancel     context.CancelFunc
	generation *controlQUICGeneration
	err        error
	superseded bool
}

func (b *bulkConn) close(reason string) {
	if b.idleTimer != nil {
		b.idleTimer.Stop()
		b.idleTimer = nil
	}
	if b.conn != nil {
		_ = b.conn.CloseWithError(0, reason)
	}
	if b.packet != nil {
		_ = b.packet.Close()
	}
}

const (
	bulkPoolIdleTimeout  = 30 * time.Second
	defaultFallbackGrace = 2 * time.Second
)

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.RemoteAddr == "" {
		return nil, errors.New("client remote address is required")
	}
	if err := validateLocalAddressSpec(cfg.LocalAddress); err != nil {
		return nil, err
	}
	if cfg.TLSConfig == nil {
		return nil, errors.New("client TLS configuration is required")
	}
	// ChunkSize is a sending policy: how much of a byte stream one DATA frame
	// carries. It is not a receive limit -- protocol.MaxPayload is, and it is
	// fixed by the wire version -- so an out-of-range value is corrected to the
	// default rather than allowed to produce frames the peer must reject.
	if cfg.ChunkSize <= 0 || cfg.ChunkSize > protocol.MaxPayload {
		cfg.ChunkSize = defaultChunkSize
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.HandshakeTimeout <= 0 {
		// Long enough for the first connection to an erasing path. The QUIC
		// handshake alone takes about five seconds at 42% loss -- its packets
		// are large, they are lost as often as anything else, and the probe
		// timeouts that recover them double -- and this bound has to cover
		// that and the session's own exchange after it. At ten seconds the
		// first connection was a coin flip, and it is the one connection every
		// flow afterwards is built on.
		cfg.HandshakeTimeout = 30 * time.Second
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
		cfg.MaxSessions = defaultClientMaxSessions
	}
	if cfg.MaxSessions > maxConfiguredSessions {
		return nil, fmt.Errorf("maximum sessions must not exceed %d", maxConfiguredSessions)
	}
	if cfg.SessionLimit == nil {
		limit, err := NewSessionLimit(cfg.MaxSessions)
		if err != nil {
			return nil, err
		}
		cfg.SessionLimit = limit
	} else if cfg.SessionLimit.shared == nil {
		return nil, errors.New("shared session limit is not initialized")
	}
	if cfg.MaxPendingOpens <= 0 {
		cfg.MaxPendingOpens = defaultMaxPendingOpens
	}
	if cfg.MaxPendingOpens > maxConfiguredSessions {
		return nil, fmt.Errorf("maximum pending opens must not exceed %d", maxConfiguredSessions)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Metrics == nil {
		cfg.Metrics = metrics.New()
	}
	if cfg.Transport == "" {
		cfg.Transport = TransportQUIC
	}
	if cfg.Transport != TransportQUIC {
		return nil, fmt.Errorf("unsupported client transport %q", cfg.Transport)
	}
	if cfg.ProviderID == "" {
		cfg.ProviderID = "queqiao"
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
	// The reserve is withheld from bulk traffic, so a reserve equal to the
	// whole budget leaves bulk not merely slow but unable to send a byte: the
	// budget has no bulk capacity to admit against and refuses every bulk
	// request outright. Require the reserve to leave something behind.
	if cfg.AggregateBytesPerSec != 0 && cfg.InteractiveReserveBytesPerSec >= cfg.AggregateBytesPerSec {
		return nil, errors.New("interactive reserve must leave bulk capacity below the aggregate byte budget")
	}
	// A caller may supply one budget shared by several clients, so that a
	// multi-provider process paces to the configured total instead of offering
	// that total once per provider. The chunk cap below is then measured
	// against the shared budget, which is the one these flows will admit
	// against.
	budget := cfg.Budget
	if budget == nil {
		budget = NewAggregateBudget(cfg.AggregateBytesPerSec, cfg.InteractiveReserveBytesPerSec)
		cfg.Budget = budget
	}
	// Before resolveMemoryLimits: the per-flow send budget is checked against
	// the chunk size, and the chunk that has to fit there is the corrected one.
	cfg.ChunkSize = chunkSizeForBudget(cfg.ChunkSize, budget)
	if err := (flowWindows{
		stream: cfg.StreamReceiveWindow, connection: cfg.ConnectionReceiveWindow,
		maxStream: cfg.MaxStreamReceiveWindow, maxConnection: cfg.MaxConnectionReceiveWindow,
		maxStreams: cfg.MaxIncomingStreams,
	}).validate(); err != nil {
		return nil, err
	}
	memoryLimits, sendMemory, receiveMemory, err := resolveMemoryLimits(cfg.MemoryLimits, cfg.ChunkSize)
	if err != nil {
		return nil, err
	}
	// A misspelled class name fails here rather than matching nothing at
	// runtime, where it would be indistinguishable from a rule whose workload
	// never appeared.
	if err := cfg.Profile.ValidateHints(); err != nil {
		return nil, fmt.Errorf("client profile: %w", err)
	}
	return &Client{
		cfg:           cfg,
		udpHealth:     newUDPHealth(cfg.UDPFailureThreshold, cfg.UDPCooldown),
		budget:        budget,
		metrics:       cfg.Metrics,
		sessionLimit:  cfg.SessionLimit,
		pendingOpens:  make(chan struct{}, cfg.MaxPendingOpens),
		sendMemory:    sendMemory,
		receiveMemory: receiveMemory,
		memoryLimits:  memoryLimits,
	}, nil
}

func (c *Client) MemoryStats() MemoryStats {
	return MemoryStats{Send: c.sendMemory.Snapshot(), Receive: c.receiveMemory.Snapshot()}
}

func (c *Client) windows() flowWindows {
	return flowWindows{
		stream: c.cfg.StreamReceiveWindow, connection: c.cfg.ConnectionReceiveWindow,
		maxStream: c.cfg.MaxStreamReceiveWindow, maxConnection: c.cfg.MaxConnectionReceiveWindow,
		maxStreams: c.cfg.MaxIncomingStreams, codedQueue: c.memoryLimits.eventQueue,
	}
}

// NewAggregateBudget builds one byte budget several clients can share, so a
// process running many clients paces to the configured total instead of
// offering that total once per client. A zero rate means unpaced.
func NewAggregateBudget(totalBytesPerSec, reserveBytesPerSec uint64) *limiter.Budget {
	return limiter.New(limiter.Config{
		TotalBytesPerSec: totalBytesPerSec, ReserveBytesPerSec: reserveBytesPerSec,
	})
}

// Metrics exposes aggregate counters for an optional operator endpoint.
func (c *Client) Metrics() *metrics.Registry { return c.metrics }

func (c *Client) admitPendingOpen() bool {
	if c.pendingOpens == nil {
		return true
	}
	select {
	case c.pendingOpens <- struct{}{}:
		return true
	default:
		return false
	}
}

func (c *Client) releasePendingOpen() {
	if c.pendingOpens != nil {
		<-c.pendingOpens
	}
}

// Start watches the uplink and measures the path in the background. It never
// blocks: an embedding host constructs its client before the peer it will
// talk to is necessarily listening, and a prewarm that ran inline would either
// hold startup for its whole budget or spend the budget on a refused dial.
// The first flow dials on its own account when the prewarm did not land.
func (c *Client) Start(ctx context.Context) {
	c.startOnce.Do(func() { c.start(ctx) })
}

func (c *Client) start(ctx context.Context) {
	uplink := c.currentUplink()
	go c.prewarmPath(ctx)
	go c.watchUplink(ctx, uplink)
}

// Close stops the client and closes its QUIC connections.
func (c *Client) Close() error {
	c.CloseWithError(os.ErrClosed)
	return nil
}

// CloseWithError abandons every pooled connection. It is safe to call more
// than once; flows in flight on those connections fail and recover on the
// next flow.
func (c *Client) CloseWithError(_ error) {
	c.closeQUICPool()
}

// CloseIdleConnections retires a pooled QUIC generation that carries no flow,
// so a network change does not wait for a timeout to discard it. A generation
// still in use is the flows' own and is left alone.
func (c *Client) CloseIdleConnections() {
	c.quicMu.Lock()
	generation := c.quicGeneration
	active := c.quicPoolActive.Load()
	c.quicMu.Unlock()
	if generation != nil && active == 0 {
		c.retireControlQUICGeneration(generation, "queqiao idle pooled connection")
	}
}

// closeQUICPool is called when the client stops. It is safe to call more
// than once and closes the packet socket owned by a locally-bound QUIC dial.
func (c *Client) closeQUICPool() {
	c.closeControlQUICPool("queqiao client pool reset")
	c.closeBulkQUICPool("queqiao bulk pool stopped")
}

func (c *Client) closeControlQUICPool(reason string) {
	c.quicMu.Lock()
	c.quicEpoch++
	generation, dial := c.quicGeneration, c.quicDial
	c.quicGeneration, c.quicDial = nil, nil
	c.quicMu.Unlock()
	if dial != nil {
		dial.cancel()
	}
	if generation != nil {
		generation.close(reason)
	}
}

func (c *Client) closeBulkQUICPool(reason string) {
	c.bulkMu.Lock()
	bulkConns := c.bulkConns
	c.bulkConns = nil
	c.bulkMu.Unlock()
	for _, entry := range bulkConns {
		entry.close(reason)
	}
}

// DialConn opens one flow and returns the application side of it. onClose, when
// given, receives the flow's terminal error exactly once.
func (c *Client) DialConn(ctx context.Context, destination string, onClose func(error)) (net.Conn, error) {
	if !c.admitPendingOpen() {
		return nil, errors.New("local pending-open limit reached")
	}
	flowOpenStarted := time.Now()
	flow, err := c.openFlowWithRetries(ctx, destination)
	c.releasePendingOpen()
	if err != nil {
		return nil, fmt.Errorf("remote flow open failed: %w", err)
	}
	c.cfg.Logger.Debug("local flow opened via DialConn", "transport", flow.kind, "duration", time.Since(flowOpenStarted))

	appConn, flowConn := newStreamPipe()
	notified := false
	notifyClose := func(err error) {
		if onClose == nil || notified {
			return
		}
		notified = true
		onClose(err)
	}

	flowSession := newMultipathFlowWithMemory(ctx, flowConn, flow.sessionID, flow.flowID, c.cfg.ChunkSize, protocol.FlagAckUp, protocol.FlagAckDown, c.budget, c.metrics, c.cfg.Logger, c.memoryLimits, c.sendMemory, c.receiveMemory, c.classifierConfig())
	flowSession.stallWatchdogDisabled = c.disableStallWatchdogForTest
	c.declareClass(ctx, flowConn, flowSession)
	flowSession.ackRanges.Store(true)
	flowSession.idleTimeout = c.cfg.FlowIdleTimeout
	flowSession.maxLifetime = c.cfg.FlowMaxLifetime
	flowSession.openAckPending = flow.openPending
	if flow.openPending {
		flowSession.requireOpenConfirmation()
	}
	flowSession.tcpStriping.Store(false)
	flowSession.reserveControlLane = flow.reserveControl
	flowSession.controlLaneShared = func() bool { return c.quicPoolActive.Load() > 1 }
	if err := flowSession.addLane(&mpLane{
		id: flow.laneID, kind: flow.kind, fc: flow.fc,
		control: flow.reserveControl && flow.kind == TransportQUIC,
	}); err != nil {
		_ = flowConn.Close()
		_ = flow.fc.Close()
		flowSession.closeAll()
		return nil, err
	}

	go c.manageLanes(ctx, flowSession, flow.sessionID, flow.flowID, flow.kind)
	go func() {
		c.metrics.FlowStarted()
		stats, err := flowSession.run(ctx)
		flowComplete := err == nil || (ctx.Err() == nil && flowSession.finSent.Load() && flowSession.remoteFinSeen.Load())
		c.metrics.FlowFinished(stats.BytesSent, stats.BytesRead, !flowComplete && err != nil && !errors.Is(err, context.Canceled))
		if !flowComplete && err != nil && !errors.Is(err, context.Canceled) {
			c.cfg.Logger.Debug("flow ended with error", "destination", destination, "error", err, "sent", stats.BytesSent, "read", stats.BytesRead, "duration", stats.Ended.Sub(stats.Started).Truncate(time.Millisecond))
		} else {
			c.cfg.Logger.Debug("flow completed normally", "destination", destination, "sent", stats.BytesSent, "read", stats.BytesRead, "duration", stats.Ended.Sub(stats.Started).Truncate(time.Millisecond))
		}
		_ = appConn.Close()
		if flowComplete {
			notifyClose(nil)
		} else {
			notifyClose(err)
		}
	}()

	return appConn, nil
}

type openedFlow struct {
	fc             *frameConn
	outer          streamConn
	sessionID      [16]byte
	flowID         uint64
	laneID         uint64
	kind           TransportKind
	openPending    bool
	reserveControl bool
	tcpStriping    bool
}

type authenticatedLane struct {
	fc             *frameConn
	outer          streamConn
	sessionID      [16]byte
	kind           TransportKind
	laneID         uint64
	reserveControl bool
	tcpStriping    bool
}

func (c *Client) openFlow(ctx context.Context, destination string) (*openedFlow, error) {
	// TLS has already authenticated the device when the first application frame
	// is sent, so OPEN never waits on a second security handshake.
	if !c.cfg.EnableQUICPool {
		return c.openInitialFlow(ctx, destination)
	}
	return c.openFlowMode(ctx, destination, false)
}

// openInitialFlow establishes a dedicated mutually authenticated connection
// and sends OPEN as its first application frame. AUTO preserves the normal UDP
// preference and prepares a delayed TCP standby behind the QUIC candidate.
func (c *Client) openInitialFlow(ctx context.Context, destination string) (*openedFlow, error) {
	payload, err := session.EncodeDestination(destination)
	if err != nil {
		return nil, err
	}
	return c.dialPipelinedCandidate(ctx, TransportQUIC, payload)
}

func (c *Client) dialPipelinedCandidate(ctx context.Context, kind TransportKind, payload []byte) (*openedFlow, error) {
	if c.dialPipelinedFlowForTest != nil {
		return c.dialPipelinedFlowForTest(ctx, kind, payload)
	}
	return c.dialPipelinedFlow(ctx, kind, payload)
}

func (c *Client) dialPipelinedFlow(ctx context.Context, kind TransportKind, payload []byte) (*openedFlow, error) {
	sessionID, err := session.NewSessionID()
	if err != nil {
		return nil, err
	}
	flowID, err := randomFlowID()
	if err != nil {
		return nil, err
	}
	lane, err := c.dialLaneMode(ctx, kind, sessionID, 0, false)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*openedFlow, error) {
		_ = lane.fc.Close()
		return nil, err
	}
	_ = lane.outer.SetDeadline(time.Now().Add(handshakeBound(lane.outer, c.cfg.HandshakeTimeout)))
	if err := lane.fc.Write(protocol.Frame{
		Header:  protocol.Header{Version: protocol.Version, Type: protocol.TypeOpen, SessionID: sessionID, FlowID: flowID, Class: protocol.ClassNew},
		Payload: payload,
	}); err != nil {
		return fail(fmt.Errorf("send pipelined flow open: %w", err))
	}
	if !c.cfg.WaitForOpenAcknowledgement {
		_ = lane.outer.SetDeadline(time.Time{})
		return &openedFlow{
			fc: lane.fc, outer: lane.outer, sessionID: sessionID, flowID: flowID,
			laneID: lane.laneID, kind: lane.kind, openPending: true,
			tcpStriping: false,
		}, nil
	}
	openAck, err := lane.fc.Read()
	if err != nil {
		return fail(fmt.Errorf("read pipelined flow acknowledgement: %w", err))
	}
	if openAck.Header.SessionID != sessionID || openAck.Header.FlowID != flowID {
		return fail(peerResponse(errors.New("pipelined flow acknowledgement identity mismatch")))
	}
	if openAck.Header.Type == protocol.TypeReset {
		return fail(peerResponse(errDestinationUnavailable))
	}
	if openAck.Header.Type != protocol.TypeOpenOK || len(openAck.Payload) != 0 {
		return fail(peerResponse(errors.New("invalid pipelined flow acknowledgement")))
	}
	_ = lane.outer.SetDeadline(time.Time{})
	return &openedFlow{
		fc: lane.fc, outer: lane.outer, sessionID: sessionID, flowID: flowID,
		laneID: lane.laneID, kind: lane.kind,
		tcpStriping: false,
	}, nil
}

const transientUDPSendLogInterval = 5 * time.Second

// hopDialConfig builds the port-hopping configuration for this client's QUIC
// dials from ClientConfig. A zero HopPortCount returns a zero hopDialConfig,
// which disables port hopping in dialQUICConnection. All dials share one
// HopWalk so port selection persists across connection attempts.
func (c *Client) hopDialConfig() hopDialConfig {
	if c.cfg.HopPortCount < 2 {
		return hopDialConfig{}
	}
	c.hopWalkOnce.Do(func() {
		c.hopWalk = portmux.NewHopWalk(c.cfg.HopPortCount)
	})
	return hopDialConfig{
		portCount:  c.cfg.HopPortCount,
		providerID: c.cfg.ProviderID,
		walk:       c.hopWalk,
		metrics:    c.cfg.Metrics,
		logger:     c.cfg.Logger,
	}
}

func (c *Client) observeTransientUDPSendFailure(err error) {
	if c.metrics != nil {
		c.metrics.TransientUDPSendError()
	}
	if c.cfg.Logger == nil {
		return
	}
	now := time.Now()
	previous := c.transientUDPLogNS.Load()
	if previous != 0 && now.Sub(time.Unix(0, previous)) < transientUDPSendLogInterval {
		return
	}
	if !c.transientUDPLogNS.CompareAndSwap(previous, now.UnixNano()) {
		return
	}
	c.cfg.Logger.Warn("transient UDP send failure treated as packet loss",
		"endpoint", c.cfg.RemoteAddr, "error", err)
}

// errDestinationUnavailable is the peer saying it could not reach the
// destination. It is the answer to the application's question, not a failure
// to ask it, so it is never retried.
var errDestinationUnavailable = errors.New("remote destination unavailable")

// flowOpenAttempts is how many times a flow open is tried before the
// application is told the destination is unreachable.
//
// On a path that erases 42% of packets an attempt is sometimes simply lost --
// a handshake packet goes missing and the probe timeouts that would recover it
// run past the bound. Reporting that as an unreachable destination is a lie
// about the destination, and the application's own retry is a fresh TCP
// connection and a fresh SOCKS negotiation for something this layer could have
// tried again itself.
const flowOpenAttempts = 3

// flowOpenRetryDelay uses equal jitter: every retry waits at least half of an
// exponentially growing window, while concurrent callers spread across the
// other half instead of forming another synchronized connection wave.
func flowOpenRetryDelay(failedAttempt int) time.Duration {
	if failedAttempt < 1 {
		failedAttempt = 1
	}
	window := flowOpenRetryBaseDelay << min(failedAttempt-1, 4)
	half := window / 2
	return half + randomDuration(half)
}

func (c *Client) waitBeforeFlowOpenRetry(ctx context.Context, failedAttempt int) error {
	delay := flowOpenRetryDelay(failedAttempt)
	if c.flowOpenRetryDelayForTest != nil {
		delay = c.flowOpenRetryDelayForTest(failedAttempt)
	}
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// openFlowWithRetries asks again when the path lost the asking.
//
// Only a transport failure is retried. A peer that answered -- with a reset,
// because the destination refused or does not exist -- has told the
// application something true, and asking again would only delay it.
func (c *Client) openFlowWithRetries(ctx context.Context, destination string) (*openedFlow, error) {
	var err error
	for attempt := 1; attempt <= flowOpenAttempts; attempt++ {
		var flow *openedFlow
		flow, err = c.openOnce(ctx, destination)
		if err == nil {
			if attempt > 1 {
				c.cfg.Logger.Debug("flow opened after a lost attempt", "attempts", attempt)
			}
			return flow, nil
		}
		if peerResponded(err) || ctx.Err() != nil {
			return nil, err
		}
		c.cfg.Logger.Debug("flow open attempt failed", "attempt", attempt, "error", err)
		if attempt < flowOpenAttempts {
			if waitErr := c.waitBeforeFlowOpenRetry(ctx, attempt); waitErr != nil {
				return nil, waitErr
			}
		}
	}
	return nil, err
}

// openOnce is one attempt, indirected so a test can stand in for the network.
func (c *Client) openOnce(ctx context.Context, destination string) (*openedFlow, error) {
	if c.openFlowForTest != nil {
		return c.openFlowForTest()
	}
	return c.openFlow(ctx, destination)
}

func (c *Client) openFlowMode(ctx context.Context, destination string, _ bool) (*openedFlow, error) {
	payload, err := session.EncodeDestination(destination)
	if err != nil {
		return nil, err
	}
	lane, err := c.chooseAuthenticatedLane(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*openedFlow, error) {
		_ = lane.fc.Close()
		return nil, err
	}
	_ = lane.outer.SetDeadline(time.Now().Add(handshakeBound(lane.outer, c.cfg.HandshakeTimeout)))
	flowID, err := randomFlowID()
	if err != nil {
		return fail(err)
	}
	openFlags := uint16(0)
	if lane.reserveControl {
		openFlags |= protocol.FlagReserveControl
	}
	if err := lane.fc.Write(protocol.Frame{
		Header:  protocol.Header{Version: protocol.Version, Type: protocol.TypeOpen, Flags: openFlags, SessionID: lane.sessionID, FlowID: flowID, Class: protocol.ClassNew},
		Payload: payload,
	}); err != nil {
		return fail(fmt.Errorf("send flow open: %w", err))
	}
	if !c.cfg.WaitForOpenAcknowledgement {
		_ = lane.outer.SetDeadline(time.Time{})
		return &openedFlow{
			fc: lane.fc, outer: lane.outer, sessionID: lane.sessionID, flowID: flowID,
			laneID: lane.laneID, kind: lane.kind, openPending: true, reserveControl: lane.reserveControl,
			tcpStriping: lane.tcpStriping,
		}, nil
	}
	response, err := lane.fc.Read()
	if err != nil {
		return fail(fmt.Errorf("read flow open acknowledgement: %w", err))
	}
	if response.Header.SessionID != lane.sessionID || response.Header.FlowID != flowID {
		return fail(peerResponse(errors.New("flow open acknowledgement identity mismatch")))
	}
	if response.Header.Type == protocol.TypeReset {
		return fail(peerResponse(errDestinationUnavailable))
	}
	if response.Header.Type != protocol.TypeOpenOK || len(response.Payload) != 0 {
		return fail(peerResponse(errors.New("invalid flow open acknowledgement")))
	}
	_ = lane.outer.SetDeadline(time.Time{})
	return &openedFlow{
		fc: lane.fc, outer: lane.outer, sessionID: lane.sessionID, flowID: flowID,
		laneID: lane.laneID, kind: lane.kind, reserveControl: lane.reserveControl,
		tcpStriping: lane.tcpStriping,
	}, nil
}

func resetCode(payload []byte) session.ResetCode {
	if len(payload) == 0 {
		return 0
	}
	return session.ResetCode(payload[0])
}

func encodeLaneID(laneID uint64) []byte {
	var payload [8]byte
	binary.BigEndian.PutUint64(payload[:], laneID)
	return payload[:]
}

func (c *Client) dialAuthenticatedLane(ctx context.Context, kind TransportKind) (*authenticatedLane, error) {
	sessionID, err := session.NewSessionID()
	if err != nil {
		return nil, err
	}
	return c.dialLane(ctx, kind, sessionID, 0)
}

func (c *Client) dialJoinLane(ctx context.Context, kind TransportKind, sessionID [16]byte, laneID uint64) (*authenticatedLane, error) {
	return c.dialLaneMode(ctx, kind, sessionID, laneID, false)
}

func (c *Client) dialLane(ctx context.Context, kind TransportKind, sessionID [16]byte, laneID uint64) (*authenticatedLane, error) {
	return c.dialLaneMode(ctx, kind, sessionID, laneID, c.cfg.EnableQUICPool)
}

// dialLaneMode uses the shared QUIC stream pool only for a flow's initial
// control stream. Additional lanes are independent QUIC connections: they
// provide true bulk capacity and independent loss paths, while the pooled
// control stream remains available for short/interactive traffic.
func (c *Client) dialLaneMode(ctx context.Context, kind TransportKind, sessionID [16]byte, laneID uint64, pooled bool) (*authenticatedLane, error) {
	dialStarted := time.Now()
	var outer streamConn
	var err error
	reserveControl := false
	switch kind {
	case TransportQUIC:
		ccfg := congestionConfig{
			kind:                   c.cfg.Congestion,
			brutalBytesPerSecond:   c.cfg.BrutalBytesPerSec,
			adaptiveMinBytesPerSec: c.cfg.AdaptiveMinBytesSec,
			adaptiveMaxBytesPerSec: c.cfg.AdaptiveMaxBytesSec,
		}
		if pooled {
			outer, err = c.dialPooledQUICLane(ctx, ccfg)
			reserveControl = true
		} else {
			outer, err = dialQUIC(ctx, c.cfg.Dialer, c.cfg.RemoteAddr, c.cfg.TLSConfig, c.cfg.Password, c.cfg.DialTimeout, c.cfg.LocalAddress, c.cfg.SocketControl, c.observeTransientUDPSendFailure, ccfg, c.windows(), c.hopDialConfig())
		}
	default:
		return nil, fmt.Errorf("cannot dial transport %q", kind)
	}
	if err != nil {
		return nil, transportError(kind, err)
	}
	outerReady := time.Now()
	_ = outer.SetDeadline(time.Now().Add(handshakeBound(outer, c.cfg.HandshakeTimeout)))
	fc := newFrameConnLimited(outer, c.memoryLimits.frameReadBuffer, c.memoryLimits.eventQueue)
	fc.setPacketsOnStream(c.cfg.UDPOnStream)
	_ = outer.SetDeadline(time.Time{})
	c.cfg.Logger.Debug("outer lane authenticated", "transport", kind, "dial_duration", outerReady.Sub(dialStarted), "pooled", pooled)
	return &authenticatedLane{
		fc: fc, outer: outer, sessionID: sessionID, kind: kind, laneID: laneID,
		reserveControl: reserveControl,
		tcpStriping:    false,
	}, nil
}

func closeAuthenticatedLane(lane *authenticatedLane) {
	if lane == nil {
		return
	}
	if lane.fc != nil {
		_ = lane.fc.Close()
	} else if lane.outer != nil {
		_ = lane.outer.Close()
	}
}

// dialPooledQUICLane opens a stream on the current shared QUIC generation.
// Connection creation is singleflight, while stream opens are concurrent:
// after an outage one handshake rebuilds the pool and every surviving logical
// flow opens its own replacement stream on it.
func (c *Client) dialPooledQUICLane(ctx context.Context, ccfg congestionConfig) (streamConn, error) {
	dialCtx := ctx
	var cancel context.CancelFunc
	if c.cfg.DialTimeout > 0 {
		dialCtx, cancel = context.WithTimeout(ctx, c.cfg.DialTimeout)
		defer cancel()
	}
	generation, err := c.acquireControlQUICGeneration(dialCtx, ccfg)
	if err != nil {
		return nil, err
	}
	stream, err := generation.conn.OpenStreamSync(dialCtx)
	if err != nil {
		if generation.conn.Context().Err() != nil {
			c.retireControlQUICGeneration(generation, "queqiao pooled connection failed")
		}
		return nil, err
	}
	// Track how many flows share the control connection. Bulk isolation is
	// only worth its cost when there is something to protect.
	c.quicPoolActive.Add(1)
	outer := &controlPoolStreamConn{
		quicStreamConn: &quicStreamConn{stream: stream, conn: generation.conn, controller: generation.controller, closeConn: false, bulk: connBulkPath(generation.conn, c.memoryLimits.eventQueue)},
		owner:          c, generation: generation,
	}
	return outer, nil
}

func (c *Client) acquireControlQUICGeneration(ctx context.Context, ccfg congestionConfig) (*controlQUICGeneration, error) {
	for {
		// Never create a client-owned background dial on behalf of work that is
		// already gone. This also closes the shutdown race where a waiter wakes
		// after its old epoch was superseded and would otherwise start one last
		// connection before noticing cancellation below.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.quicMu.Lock()
		if generation := c.quicGeneration; generation != nil && generation.conn.Context().Err() == nil {
			c.quicMu.Unlock()
			return generation, nil
		}
		stale := c.quicGeneration
		c.quicGeneration = nil
		attempt := c.quicDial
		if attempt == nil {
			c.quicEpoch++
			dialCtx, cancel := context.WithCancel(context.Background())
			attempt = &controlQUICDial{epoch: c.quicEpoch, done: make(chan struct{}), cancel: cancel}
			c.quicDial = attempt
			go c.runControlQUICDial(dialCtx, attempt, ccfg)
		}
		c.quicMu.Unlock()
		if stale != nil {
			stale.close("queqiao stale pooled connection")
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-attempt.done:
		}
		if attempt.superseded {
			continue
		}
		if attempt.err != nil {
			return nil, attempt.err
		}
		if attempt.generation != nil {
			return attempt.generation, nil
		}
		// A path reset can supersede an in-flight dial. Its waiters retry against
		// the new epoch instead of inheriting a connection bound to the old path.
	}
}

func (c *Client) runControlQUICDial(ctx context.Context, attempt *controlQUICDial, ccfg congestionConfig) {
	conn, packet, err := dialQUICConnection(ctx, c.cfg.Dialer, c.cfg.RemoteAddr, c.cfg.TLSConfig, c.cfg.Password, c.cfg.DialTimeout, c.cfg.LocalAddress, c.cfg.SocketControl, c.observeTransientUDPSendFailure, c.windows(), c.hopDialConfig())
	var generation *controlQUICGeneration
	if err == nil {
		generation = &controlQUICGeneration{
			id: attempt.epoch, conn: conn, packet: packet,
			controller: configureQUICController(conn, ccfg),
		}
	}

	c.quicMu.Lock()
	current := c.quicDial == attempt && c.quicEpoch == attempt.epoch
	if current {
		c.quicDial = nil
		if err == nil {
			c.quicGeneration = generation
			attempt.generation = generation
		} else {
			attempt.err = err
		}
	}
	c.quicMu.Unlock()
	if !current && generation != nil {
		generation.close("queqiao superseded pooled connection")
	}
	if !current {
		attempt.superseded = true
	}
	close(attempt.done)
}

func (c *Client) retireControlQUICGeneration(generation *controlQUICGeneration, reason string) {
	if generation == nil {
		return
	}
	c.quicMu.Lock()
	if c.quicGeneration == generation {
		c.quicGeneration = nil
	}
	c.quicMu.Unlock()
	generation.close(reason)
}

// laneJoinResult carries an asynchronous lane join back to the decision loop.
type laneJoinResult struct {
	lane *mpLane
	id   uint64
	err  error
	// replacement distinguishes a join opened because the flow has no lane
	// left from one opened to widen a healthy bundle. Only the first is a
	// replacement attempt, and the result arrives too late to tell by looking
	// at the flow: by then it may have recovered or died.
	replacement bool
}

// errLaneJoinRejected reports that the peer answered a lane join and refused
// it, as opposed to the join failing to complete. The distinction decides two
// things: a refusal is not evidence that UDP is unhealthy -- the handshake
// completed and the peer replied, so marking the transport down here would
// eventually push unrelated flows onto the TCP fallback -- and it is a policy
// answer that will not change during this flow, so the search should stop
// rather than back off and retry. A peer pinned to a lower lane ceiling than
// this endpoint is the ordinary way to reach it.
var errLaneJoinRejected = errors.New("lane join rejected")

// errLaneJoinCapacity is a refusal by the peer's own lane admission ceiling,
// in contrast to errLaneJoinRejected's permanent answers about the session.
// It says nothing about the session and nothing about the path: the flow the
// lane would join is alive, and the answer can change as lanes come and go,
// so it neither ends a rescue round early nor marks the session unresumable.
// The ordinary way to reach it is several rescue JOINs racing the peer's
// lane cap, where all but the first admitted are supposed to lose.
var errLaneJoinCapacity = errors.New("lane join refused by peer lane capacity")

// errLaneJoinTCPMode is the peer saying the flow has already committed to
// TCP fallback, so a QUIC lane can never be admitted to it. It stays an
// errLaneJoinRejected -- a configuration-pinned QUIC client has no TCP commit
// to make and must fail the flow fast as before -- but an AUTO recovery path
// matches it specifically to commit to TCP at once instead of spending its
// replacement grace on QUIC retries the peer has already ruled out.
var errLaneJoinTCPMode = fmt.Errorf("%w: flow switched to TCP fallback", errLaneJoinRejected)

// errBulkConnectionLimit is a scheduling answer, not a transport failure.
// The caller keeps the flow on its pooled control connection when every
// isolation slot is occupied. Falling back to a dedicated connection here
// would silently bypass the descriptor and handshake budget this limit exists
// to enforce.
var errBulkConnectionLimit = errors.New("bulk lane connection limit reached")

func dedicatedBulkFallbackAllowed(err error) bool {
	return err != nil &&
		!errors.Is(err, errBulkConnectionLimit) &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded)
}

func (c *Client) openJoinLane(ctx context.Context, kind TransportKind, sessionID [16]byte, flowID, laneID uint64) (*mpLane, error) {
	if kind == TransportQUIC && c.cfg.EnableQUICPool {
		if lane, poolErr := c.openPooledJoinLane(ctx, sessionID, flowID, laneID); poolErr == nil {
			return lane, nil
		} else if !dedicatedBulkFallbackAllowed(poolErr) {
			return nil, poolErr
		} else {
			c.cfg.Logger.Debug("pooled lane join unavailable; using dedicated lane", "error", poolErr)
		}
	}
	lane, err := c.dialJoinLane(ctx, TransportQUIC, sessionID, laneID)
	if err != nil {
		return nil, err
	}
	return c.completeLaneJoin(ctx, lane, flowID, 0)
}

// openControlPoolJoinLane restores the control role on the one replacement
// generation shared by every affected flow. It is intentionally separate from
// openPooledJoinLane: that pool gives a bulk flow an exclusive congestion
// controller, while this pool is the multiplexed control failure domain being
// rebuilt.
func (c *Client) openControlPoolJoinLane(ctx context.Context, sessionID [16]byte, flowID, laneID uint64) (*mpLane, error) {
	lane, err := c.dialLaneMode(ctx, TransportQUIC, sessionID, laneID, true)
	if err != nil {
		return nil, err
	}
	return c.completeLaneJoin(ctx, lane, flowID, protocol.FlagReserveControl)
}

func (c *Client) completeLaneJoin(ctx context.Context, lane *authenticatedLane, flowID uint64, flags uint16) (*mpLane, error) {
	// Dial cancellation alone does not interrupt the subsequent JOIN read or
	// write. Close this lane's stream when its recovery round is cancelled.
	stopCancel := context.AfterFunc(ctx, func() { _ = lane.fc.Close() })
	defer stopCancel()
	_ = lane.outer.SetDeadline(time.Now().Add(handshakeBound(lane.outer, c.cfg.HandshakeTimeout)))
	if err := lane.fc.Write(protocol.Frame{Header: protocol.Header{
		Version: protocol.Version, Type: protocol.TypeJoin, Flags: flags,
		SessionID: lane.sessionID, FlowID: flowID, Class: protocol.ClassBulk,
	}, Payload: encodeLaneID(lane.laneID)}); err != nil {
		_ = lane.fc.Close()
		return nil, err
	}
	response, err := lane.fc.Read()
	if err != nil {
		_ = lane.fc.Close()
		return nil, err
	}
	if response.Header.Type == protocol.TypeReset && response.Header.SessionID == lane.sessionID && response.Header.FlowID == flowID {
		_ = lane.fc.Close()
		if len(response.Payload) > 1 {
			switch session.ResetCode(response.Payload[0]) {
			case session.ResetFlowLimit:
				return nil, fmt.Errorf("%w: %s", errLaneJoinCapacity, string(response.Payload[1:]))
			case session.ResetTransport:
				return nil, fmt.Errorf("%w: %s", errLaneJoinTCPMode, string(response.Payload[1:]))
			}
			return nil, fmt.Errorf("%w: %s", errLaneJoinRejected, string(response.Payload[1:]))
		}
		return nil, errLaneJoinRejected
	}
	if response.Header.Type != protocol.TypeOpenOK || response.Header.SessionID != lane.sessionID || response.Header.FlowID != flowID || len(response.Payload) != 0 {
		_ = lane.fc.Close()
		return nil, errors.New("invalid lane join acknowledgement")
	}
	if !stopCancel() {
		_ = lane.fc.Close()
		return nil, ctx.Err()
	}
	_ = lane.outer.SetDeadline(time.Time{})
	return &mpLane{
		id: lane.laneID, kind: lane.kind, fc: lane.fc,
		tcpStriping: lane.tcpStriping,
		control:     flags&protocol.FlagReserveControl != 0,
	}, nil
}

// openPooledJoinLane uses a bounded, separately authenticated QUIC connection
// for bulk streams. Mutual TLS authenticates the connection; the JOIN frame
// only identifies the existing flow and lane and cannot change its principal.
func (c *Client) openPooledJoinLane(ctx context.Context, sessionID [16]byte, flowID, laneID uint64) (*mpLane, error) {
	started := time.Now()
	outer, err := c.openBulkPoolStream(ctx)
	if err != nil {
		return nil, err
	}
	fc := newFrameConnLimited(outer, c.memoryLimits.frameReadBuffer, c.memoryLimits.eventQueue)
	fc.setPacketsOnStream(c.cfg.UDPOnStream)
	lane, err := c.completeLaneJoin(ctx, &authenticatedLane{
		fc: fc, outer: outer, sessionID: sessionID, kind: TransportQUIC, laneID: laneID,
	}, flowID, 0)
	if err != nil {
		return nil, err
	}
	c.cfg.Logger.Debug("bulk lane joined", "lane", laneID, "duration", time.Since(started))
	return lane, nil
}

// openBulkPoolStream reserves one secondary connection and opens its lane
// stream. Connections are created lazily, so one-shot and interactive-only
// clients pay no extra QUIC handshake, and each is reserved exclusively for
// the lane it carries so concurrent lanes keep independent 4-tuples and
// congestion state.
func (c *Client) openBulkPoolStream(ctx context.Context) (streamConn, error) {
	started := time.Now()
	dialCtx := ctx
	var cancel context.CancelFunc
	if c.cfg.DialTimeout > 0 {
		dialCtx, cancel = context.WithTimeout(ctx, c.cfg.DialTimeout)
		defer cancel()
	}
	entry, err := c.reserveBulkConn(dialCtx)
	if err != nil {
		return nil, err
	}
	stream, err := entry.conn.OpenStreamSync(dialCtx)
	if err != nil {
		c.releaseBulkConn(entry, entry.conn.Context().Err() != nil)
		return nil, err
	}
	c.cfg.Logger.Debug("bulk pool stream opened", "duration", time.Since(started), "connections", c.bulkConnCount())
	return &bulkPoolStreamConn{
		quicStreamConn: &quicStreamConn{stream: stream, conn: entry.conn, controller: entry.controller, closeConn: false, bulk: connBulkPath(entry.conn, c.memoryLimits.eventQueue)},
		owner:          c, entry: entry,
	}, nil
}

// reserveBulkConn returns an idle authenticated connection, or establishes a
// new one when every existing connection is already carrying a lane.
func (c *Client) reserveBulkConn(ctx context.Context) (*bulkConn, error) {
	c.bulkMu.Lock()
	live := c.bulkConns[:0]
	for _, entry := range c.bulkConns {
		if entry.conn.Context().Err() != nil && !entry.busy {
			entry.close("queqiao stale bulk pool")
			continue
		}
		live = append(live, entry)
	}
	c.bulkConns = live
	for _, entry := range c.bulkConns {
		if !entry.busy && entry.conn.Context().Err() == nil {
			entry.busy = true
			if entry.idleTimer != nil {
				entry.idleTimer.Stop()
				entry.idleTimer = nil
			}
			c.bulkMu.Unlock()
			return entry, nil
		}
	}
	if len(c.bulkConns) >= c.maxBulkConns() {
		c.bulkMu.Unlock()
		return nil, errBulkConnectionLimit
	}
	c.bulkMu.Unlock()

	// The handshake is deliberately performed without the pool mutex so that
	// one slow secondary handshake cannot block every other lane join.
	entry, err := c.dialBulkConn(ctx)
	if err != nil {
		return nil, err
	}
	c.bulkMu.Lock()
	if len(c.bulkConns) >= c.maxBulkConns() {
		c.bulkMu.Unlock()
		entry.close("queqiao bulk pool limit reached")
		return nil, errBulkConnectionLimit
	}
	entry.busy = true
	c.bulkConns = append(c.bulkConns, entry)
	c.bulkMu.Unlock()
	return entry, nil
}

// isolatedBulkConns bounds the secondary connections one client may hold.
//
// It is a count of concurrently isolated bulk flows, not of lanes. A flow's
// data lives on one lane, so a flow needs at most one of these -- but several
// bulk flows can be in flight at once, and each has to have its own or
// isolation is a queue rather than a policy. Capping this at one during the
// striping excision would have let exactly one bulk flow at a time leave the
// shared connection, which is the case the eight-flow live measurement is
// about.
//
// Eight is what the lane ceiling used to permit and is a bound on descriptors
// and handshakes rather than a tuning choice; a ninth concurrent bulk flow
// stays on the pooled connection, which is where it started.
const isolatedBulkConns = 8

func (c *Client) maxBulkConns() int { return c.memoryLimits.maxBulkConnections }

func (c *Client) bulkConnCount() int {
	c.bulkMu.Lock()
	defer c.bulkMu.Unlock()
	return len(c.bulkConns)
}

func (c *Client) dialBulkConn(ctx context.Context) (*bulkConn, error) {
	started := time.Now()
	conn, packet, err := dialQUICConnection(ctx, c.cfg.Dialer, c.cfg.RemoteAddr, c.cfg.TLSConfig, c.cfg.Password, c.cfg.DialTimeout, c.cfg.LocalAddress, c.cfg.SocketControl, c.observeTransientUDPSendFailure, c.windows(), c.hopDialConfig())
	if err != nil {
		return nil, err
	}
	entry := &bulkConn{conn: conn, packet: packet}
	entry.controller = configureQUICController(conn, congestionConfig{
		kind:                   c.cfg.Congestion,
		brutalBytesPerSecond:   c.cfg.BrutalBytesPerSec,
		adaptiveMinBytesPerSec: c.cfg.AdaptiveMinBytesSec,
		adaptiveMaxBytesPerSec: c.cfg.AdaptiveMaxBytesSec,
	})
	c.cfg.Logger.Debug("bulk QUIC pool authenticated", "duration", time.Since(started))
	return entry, nil
}

// controlPoolStreamConn keeps the count of flows sharing the pooled control
// connection accurate, which is what decides whether a bulk flow should move
// off it.
type controlPoolStreamConn struct {
	*quicStreamConn
	owner      *Client
	generation *controlQUICGeneration
	once       sync.Once
}

func (s *controlPoolStreamConn) transportFailed(err error) {
	if s.generation == nil {
		return
	}
	// A QUIC connection can remain superficially open after one of its streams
	// has stopped making progress. In that state Context().Err() is still nil,
	// so keeping the generation makes every later flow reuse the same poisoned
	// pool. A real I/O timeout is sufficient evidence to retire the generation;
	// ordinary per-stream EOFs and application closes must not evict it.
	if s.generation.conn.Context().Err() != nil || pooledTransportTimedOut(err) {
		s.owner.retireControlQUICGeneration(s.generation, "queqiao pooled connection failed")
	}
}

func pooledTransportTimedOut(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

func (s *controlPoolStreamConn) Close() error {
	err := s.quicStreamConn.Close()
	s.once.Do(func() {
		if remaining := s.owner.quicPoolActive.Add(-1); remaining < 0 {
			s.owner.quicPoolActive.Store(0)
		}
	})
	return err
}

type bulkPoolStreamConn struct {
	*quicStreamConn
	owner *Client
	entry *bulkConn
	once  sync.Once
}

func (s *bulkPoolStreamConn) Close() error {
	err := s.quicStreamConn.Close()
	s.once.Do(func() { s.owner.releaseBulkConn(s.entry, s.entry.conn.Context().Err() != nil) })
	return err
}

// releaseBulkConn returns a connection to the idle set, or discards it when
// its transport is already dead. An idle connection is retained briefly so a
// following flow can skip the handshake, then closed.
func (c *Client) releaseBulkConn(entry *bulkConn, dead bool) {
	c.bulkMu.Lock()
	entry.busy = false
	if dead {
		remaining := c.bulkConns[:0]
		for _, existing := range c.bulkConns {
			if existing != entry {
				remaining = append(remaining, existing)
			}
		}
		c.bulkConns = remaining
		c.bulkMu.Unlock()
		entry.close("queqiao bulk pool failed")
		return
	}
	if entry.idleTimer != nil {
		entry.idleTimer.Stop()
	}
	entry.idleTimer = time.AfterFunc(bulkPoolIdleTimeout, func() { c.expireBulkConn(entry) })
	c.bulkMu.Unlock()
}

func (c *Client) expireBulkConn(entry *bulkConn) {
	c.bulkMu.Lock()
	if entry.busy {
		c.bulkMu.Unlock()
		return
	}
	remaining := c.bulkConns[:0]
	found := false
	for _, existing := range c.bulkConns {
		if existing == entry {
			found = true
			continue
		}
		remaining = append(remaining, existing)
	}
	c.bulkConns = remaining
	c.bulkMu.Unlock()
	if found {
		entry.close("queqiao bulk pool idle")
	}
}

func bulkLaneBudget(reserveControl bool) (bulk, controlReserve int) {
	if reserveControl {
		return 1, 1
	}
	return 1, 0
}

func (c *Client) manageLanes(ctx context.Context, flow *multipathFlow, sessionID [16]byte, flowID uint64, initialKind TransportKind) {
	if initialKind != TransportQUIC {
		return
	}
	c.manageQUICLanes(ctx, flow, sessionID, flowID)
}

func (c *Client) manageQUICLanes(ctx context.Context, flow *multipathFlow, sessionID [16]byte, flowID uint64) {
	_, controlReserve := bulkLaneBudget(flow.reserveControlLane)
	manageCtx, manageCancel := context.WithCancel(ctx)
	defer manageCancel()
	// This goroutine is the only thing that opens a replacement lane for this
	// flow. When it returns -- budget spent, context gone, or handed off to the
	// bundle manager below, which marks the flow again when it returns in turn
	// -- the flow's replacement grace is waiting for something nobody will
	// send, and it should stop rather than leave the application in silence.
	defer flow.noteReplacementAbandoned()
	go func() {
		select {
		case <-flow.doneChan():
			manageCancel()
		case <-manageCtx.Done():
		}
	}()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	joins := make(chan laneJoinResult, 1)
	joinPending := false
	isolated := false
	var lastDecision time.Time
	var recoveryBackoff time.Duration
	var nextRecovery time.Time
	recoveryAttempts := 0
	var lastRecoveryAttempt time.Time
	var isolationBlockedUntil time.Time
	var isolationBackoff time.Duration
	isolationAttempts := 0
	var stallBackoff time.Duration
	var nextStallRescue time.Time
	for {
		select {
		case <-flow.doneChan():
			return
		case <-manageCtx.Done():
			return
		case <-flow.stallSignals():
			// The watchdog suspects the lane, not declares it dead: the flow
			// still has one, so this is a rescue beside the existing lane,
			// not a replacement for a lost one. A flow with no lane at all is
			// the outage path below, which owns that case.
			if flow.doneChanClosed() {
				return
			}
			if len(flow.healthyLanes()) == 0 {
				continue
			}
			now := time.Now()
			if now.Before(nextStallRescue) {
				continue
			}
			if err := c.runRescueRound(manageCtx, flow, sessionID, flowID); err != nil {
				if manageCtx.Err() != nil || flow.doneChanClosed() {
					return
				}
				if errors.Is(err, errLaneJoinRejected) {
					// As below: the peer's answer is permanent, so stop.
					flow.resumeRefused.Store(true)
					c.cfg.Logger.Debug("peer cannot resume this association", "flow_id", flowID, "error", err)
					return
				}
				if errors.Is(err, errLaneJoinCapacity) && flow.laneCapacityRefusals() >= maxLaneRecoveryAttempts {
					// The ceiling answer is transient only while lanes
					// genuinely come and go. This many consecutive refusals
					// without one successful round is a wedged admission slot
					// the peer cannot see, so the flow fails fast here exactly
					// as it does for a permanent refusal, and the application
					// reconnects on a fresh flow.
					flow.resumeRefused.Store(true)
					c.cfg.Logger.Debug("peer lane capacity answer persisted; giving up on this association", "flow_id", flowID, "refusals", flow.laneCapacityRefusals())
					return
				}
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					c.cfg.Logger.Warn("stall rescue unavailable", "flow_id", flowID, "error", err)
				}
				if stallBackoff == 0 {
					stallBackoff = time.Second
				} else if stallBackoff < 15*time.Second {
					stallBackoff *= 2
					if stallBackoff > 15*time.Second {
						stallBackoff = 15 * time.Second
					}
				}
				nextStallRescue = time.Now().Add(stallBackoff)
			} else {
				// A fresh lane must prove itself before the next round of
				// dials; the watchdog will re-signal if the stall is real.
				stallBackoff = 0
				nextStallRescue = time.Now().Add(time.Second)
			}
		case <-ticker.C:
			// The remote completion watcher can close its lanes just before
			// this scheduler tick. Both FIN directions are already known at
			// that point, so joining a tombstoned/unknown session would only
			// create noisy warnings and transient UDP-health penalties.
			if flow.finSent.Load() && flow.remoteFinSeen.Load() {
				flow.closeAll()
				return
			}
			for draining := true; draining; {
				select {
				case result := <-joins:
					joinPending = false
					switch {
					case result.err != nil:
						if manageCtx.Err() != nil || flow.doneChanClosed() {
							return
						}
						if errors.Is(result.err, errLaneJoinRejected) || errors.Is(result.err, errLaneJoinCapacity) {
							// The peer's ceiling, not a broken path. Keep the
							// flow where it is.
							isolated = true
							c.cfg.Logger.Debug("peer refused lane join; flow stays on the shared connection", "lane", result.id, "error", result.err)
							break
						}
						if errors.Is(result.err, errBulkConnectionLimit) {
							c.cfg.Logger.Debug("bulk isolation capacity occupied; flow stays on the shared connection", "lane", result.id)
						} else {
							c.cfg.Logger.Warn("bulk isolation lane unavailable", "lane", result.id, "error", result.err)
						}
						if isolationBackoff == 0 {
							isolationBackoff = minLaneProbeBackoff
						} else if isolationBackoff < maxLaneProbeBackoff {
							isolationBackoff *= 2
							if isolationBackoff > maxLaneProbeBackoff {
								isolationBackoff = maxLaneProbeBackoff
							}
						}
						isolationBlockedUntil = time.Now().Add(isolationBackoff)
					default:
						if err := flow.addLane(result.lane); err != nil {
							_ = result.lane.fc.Close()
							break
						}
						isolated = true
						if controlReserve > 0 && flow.laneCount() == controlReserve+1 {
							// The flow's first bulk lane is what moves it off
							// the shared control connection, which is what
							// keeps interactive traffic out of a bulk
							// congestion window. Count it so an operator can
							// see the policy act.
							c.metrics.BulkIsolated()
						}
					}
				default:
					draining = false
				}
			}
			snapshot := flow.snapshot()
			now := time.Now()
			if snapshot.HealthyLanes == 0 {
				if flow.doneChanClosed() {
					return
				}
				if recoveryAttempts >= maxLaneRecoveryAttempts {
					// Say so once, at the level a failing flow is reported at:
					// from here the flow fails immediately rather than waiting
					// out a grace nothing will arrive during.
					c.cfg.Logger.Info("lane recovery abandoned", "attempts", recoveryAttempts, "flow_id", flowID)
					return
				}
				if !nextRecovery.IsZero() && now.Before(nextRecovery) {
					continue
				}
				recoveryAttempts++
				lastRecoveryAttempt = now
				flow.noteReplacementAttempt()
				if err := c.runRescueRound(manageCtx, flow, sessionID, flowID); err != nil {
					flow.noteReplacementFailure()
					if errors.Is(err, errLaneJoinRejected) {
						// The peer answered, and its answer was that it does
						// not hold this session. That does not change: a
						// session identifier is random and is never reissued.
						// Retrying it spends the flow's whole replacement
						// grace learning the same thing, so record the refusal
						// and let the flow fail now.
						flow.resumeRefused.Store(true)
						c.cfg.Logger.Debug("peer cannot resume this association", "flow_id", flowID, "error", err)
						return
					}
					if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
						// The flow this belongs to is the whole point of the
						// line: a gateway record saying a flow failed with no
						// replacement cannot be told from one where none was
						// tried unless the attempts can be found by flow.
						c.cfg.Logger.Warn("lane recovery unavailable", "flow_id", flowID,
							"attempt", recoveryAttempts, "error", err)
					}
					if recoveryBackoff == 0 {
						recoveryBackoff = time.Second
					} else if recoveryBackoff < 15*time.Second {
						recoveryBackoff *= 2
						if recoveryBackoff > 15*time.Second {
							recoveryBackoff = 15 * time.Second
						}
					}
					nextRecovery = now.Add(recoveryBackoff)
				} else {
					recoveryBackoff = 0
					nextRecovery = time.Time{}
					lastRecoveryAttempt = time.Time{}
				}
				continue
			}
			if recoveryAttempts > 0 && !lastRecoveryAttempt.IsZero() && time.Since(lastRecoveryAttempt) >= laneRecoveryResetAfter {
				recoveryAttempts = 0
				recoveryBackoff = 0
				nextRecovery = time.Time{}
				lastRecoveryAttempt = time.Time{}
			}
			// Everything below is isolation, and it is over once it has
			// happened: a QUIC flow's data lives on one lane, so there is never
			// a second QUIC data lane to open.
			if isolated || controlReserve == 0 || joinPending {
				continue
			}
			// Isolation earns its cost only while another flow shares the
			// control connection. A bulk transfer alone on it has nothing to
			// protect, and moving it would spend a handshake and a fresh
			// congestion window for no benefit: measured on an otherwise idle
			// path that costs about 8% of bulk goodput.
			if c.quicPoolActive.Load() <= 1 {
				continue
			}
			if snapshot.Class != classifier.ClassBulk && !shouldPrewarmBulkLane(snapshot) {
				continue
			}
			// Do not consume the decision interval while the flow is still NEW
			// or INTERACTIVE. The classifier may cross its bulk byte/age
			// boundary just after such a tick.
			if !lastDecision.IsZero() && now.Sub(lastDecision) < laneDecisionInterval {
				continue
			}
			lastDecision = now
			if isolationAttempts >= maxLaneProbeAttempts || flow.doneChanClosed() ||
				now.Before(isolationBlockedUntil) {
				continue
			}
			laneID, err := flow.allocateJoinID()
			if err != nil {
				return
			}
			isolationAttempts++
			joinPending = true
			// Open the lane off the decision loop. On a saturated path the
			// join's own handshake queues behind the flow's data and has been
			// measured taking several seconds; doing it inline would leave the
			// flow blind to a lane failure meanwhile.
			go func() {
				lane, err := c.openJoinLane(manageCtx, TransportQUIC, sessionID, flowID, laneID)
				select {
				case joins <- laneJoinResult{lane: lane, id: laneID, err: err}:
				case <-manageCtx.Done():
					if lane != nil {
						_ = lane.fc.Close()
					}
				}
			}()
		}
	}
}

func shouldPrewarmBulkLane(snapshot flowSnapshot) bool {
	if snapshot.Elapsed < bulkLanePrewarmAge || snapshot.Bytes < bulkLanePrewarmBytes {
		return false
	}
	smaller, larger := snapshot.BytesUp, snapshot.BytesDown
	if smaller > larger {
		smaller, larger = larger, smaller
	}
	if smaller == 0 {
		return larger >= bulkLanePrewarmBytes
	}
	return larger/smaller >= bulkLaneAsymmetry
}

// rescueAttempt is one dial+JOIN strategy in a parallel rescue round.
type rescueAttempt func(ctx context.Context) (*mpLane, error)

// runRescueRound executes one parallel rescue round under the flow's
// in-flight guard: the stall watchdog stays silent for the round, and any
// request it managed to queue just before the guard engaged is dropped
// afterwards, because the round has just changed the state that request
// described.
func (c *Client) runRescueRound(ctx context.Context, flow *multipathFlow, sessionID [16]byte, flowID uint64) error {
	flow.rescueInFlight.Store(true)
	err := c.openParallelRescue(ctx, flow, sessionID, flowID)
	flow.rescueInFlight.Store(false)
	// The capacity streak is kept per round rather than per attempt: a round
	// is the unit the peer's ceiling answer is believed or doubted on, and
	// the attempts inside one round race exactly because only one of them is
	// supposed to win.
	if errors.Is(err, errLaneJoinCapacity) {
		flow.noteLaneCapacityRefusal()
	} else {
		flow.resetLaneCapacityRefusals()
	}
	select {
	case <-flow.stallSignals():
	default:
	}
	return err
}

// openParallelRescue installs a QUIC race winner.
func (c *Client) openParallelRescue(ctx context.Context, flow *multipathFlow, sessionID [16]byte, flowID uint64) error {
	lane, err := c.openRescueLane(ctx, flow, sessionID, flowID)
	if err != nil {
		return err
	}
	if err := c.installRecoveryLane(flow, lane); err != nil {
		return err
	}
	c.cfg.Logger.Info("lane rescue joined", "flow", flowID, "lane", lane.id, "transport", lane.kind)
	return nil
}

func (c *Client) openRescueLane(ctx context.Context, flow *multipathFlow, sessionID [16]byte, flowID uint64) (*mpLane, error) {
	if flow.finSent.Load() && flow.remoteFinSeen.Load() {
		return nil, context.Canceled
	}
	attempts := []rescueAttempt{func(ctx context.Context) (*mpLane, error) {
		return c.openQUICRecoveryLane(ctx, flow, sessionID, flowID)
	}}
	for len(attempts) < metrics.RescueAttemptSlots {
		attempts = append(attempts, func(ctx context.Context) (*mpLane, error) {
			return c.openSprayedQUICRescueJoin(ctx, flow, sessionID, flowID)
		})
	}
	lane, _, err := c.raceRescueAttempts(ctx, flow, attempts)
	return lane, err
}

// openSprayedQUICRescueJoin is one independent QUIC dial+JOIN for the
// parallel rescue: its own connection, its own handshake retransmission
// schedule, and -- through the shared hop walk -- the next port in a shuffled
// permutation of the hop pool, which makes concurrent attempts uniform over
// the available ports without repeating one.
func (c *Client) openSprayedQUICRescueJoin(ctx context.Context, flow *multipathFlow, sessionID [16]byte, flowID uint64) (*mpLane, error) {
	laneID, err := flow.allocateJoinID()
	if err != nil {
		return nil, err
	}
	lane, err := c.dialJoinLane(ctx, TransportQUIC, sessionID, laneID)
	if err != nil {
		return nil, err
	}
	return c.completeLaneJoin(ctx, lane, flowID, 0)
}

// raceRescueAttempts runs a rescue round: every attempt starts together, the
// first successful JOIN wins, and the losers' contexts are cancelled at once.
// Losing lanes are closed wherever they surface -- an attempt finishing after
// the race was decided closes its own lane, and the drain collects any that
// completed in the window before the cancellation reached them.
//
// The race is deliberately not transactional with the server, which admits
// JOINs in arrival order while the winner here is the first finisher. What
// keeps a late losing JOIN from evicting the winner's server side at the
// lane ceiling is the server: a lane is unevictable while its JOIN handshake
// is in flight and for one path-detection budget afterwards, so the loser is
// refused by capacity instead (see retireOldestLane), and a capacity refusal
// is exactly the per-attempt failure errLaneJoinCapacity carries back here.
// Past that window no role or seniority shields a lane from a newer rescue.
func (c *Client) raceRescueAttempts(ctx context.Context, flow *multipathFlow, attempts []rescueAttempt) (*mpLane, int, error) {
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// A rescue handshake must not outlive its flow.
	go func() {
		select {
		case <-flow.doneChan():
			cancel()
		case <-raceCtx.Done():
		}
	}()
	type result struct {
		lane    *mpLane
		attempt int
		err     error
	}
	results := make(chan result, len(attempts))
	for i, attempt := range attempts {
		c.metrics.LaneRescueAttempt()
		go func(i int, attempt rescueAttempt) {
			lane, err := attempt(raceCtx)
			if err == nil && lane != nil && raceCtx.Err() != nil {
				// Finished after the race was decided: close it here rather
				// than trusting the drain to see it.
				_ = lane.fc.Close()
				lane = nil
				err = context.Canceled
			}
			results <- result{lane: lane, attempt: i, err: err}
		}(i, attempt)
	}
	drain := func(pending int) {
		for ; pending > 0; pending-- {
			if loser := <-results; loser.lane != nil {
				_ = loser.lane.fc.Close()
			}
		}
	}
	pending := len(attempts)
	var firstErr error
	for pending > 0 {
		var r result
		select {
		case r = <-results:
		case <-raceCtx.Done():
			go drain(pending)
			return nil, -1, raceCtx.Err()
		}
		pending--
		if r.err == nil && r.lane != nil {
			cancel()
			go drain(pending)
			c.metrics.LaneRescueWin(r.attempt)
			return r.lane, r.attempt, nil
		}
		if errors.Is(r.err, errLaneJoinRejected) {
			// Permanent session state is shared by all QUIC attempts.
			cancel()
			go drain(pending)
			return nil, -1, r.err
		}
		if firstErr == nil {
			firstErr = r.err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("lane rescue ran no attempts")
	}
	return nil, -1, firstErr
}

// openQUICRecoveryLane never commits TCP. Pooled flows first reuse the
// shared generation; the other racers supply independent QUIC connections.
func (c *Client) openQUICRecoveryLane(ctx context.Context, flow *multipathFlow, sessionID [16]byte, flowID uint64) (*mpLane, error) {
	if flow.reserveControlLane && c.cfg.EnableQUICPool {
		laneID, err := flow.allocateJoinID()
		if err != nil {
			return nil, err
		}
		return c.openControlPoolJoinLane(ctx, sessionID, flowID, laneID)
	}
	return c.openSprayedQUICRescueJoin(ctx, flow, sessionID, flowID)
}

func (c *Client) installRecoveryLane(flow *multipathFlow, lane *mpLane) error {
	if err := flow.addLane(lane); err != nil {
		_ = lane.fc.Close()
		return err
	}
	c.metrics.LaneReplacement()
	return nil
}

func (c *Client) chooseAuthenticatedLane(ctx context.Context) (*authenticatedLane, error) {
	return c.dialAuthenticatedCandidate(ctx, TransportQUIC)
}

func (c *Client) dialAuthenticatedCandidate(ctx context.Context, kind TransportKind) (*authenticatedLane, error) {
	if c.dialAuthenticatedLaneForTest != nil {
		return c.dialAuthenticatedLaneForTest(ctx, kind)
	}
	return c.dialAuthenticatedLane(ctx, kind)
}

// classifierConfig is the flow-classification policy this client's profile
// asks for. It is read per flow rather than cached so that a profile chosen at
// startup is visible in every flow the process creates, including ones opened
// long afterwards.
func (c *Client) classifierConfig() classifier.Config {
	return classifier.DefaultConfig()
}

func (c *Client) declareClass(ctx context.Context, inner net.Conn, flow *multipathFlow) {
}
