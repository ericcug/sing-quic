package congestion

import (
	"math"
	"testing"
	"time"

	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
)

type mockRTTStats struct {
	rtt time.Duration
}

func (m *mockRTTStats) MinRTT() time.Duration                      { return m.rtt }
func (m *mockRTTStats) LatestRTT() time.Duration                   { return m.rtt }
func (m *mockRTTStats) SmoothedRTT() time.Duration                 { return m.rtt }
func (m *mockRTTStats) MeanDeviation() time.Duration               { return 0 }
func (m *mockRTTStats) MaxAckDelay() time.Duration                 { return 0 }
func (m *mockRTTStats) PTO(includeMaxAckDelay bool) time.Duration  { return 3 * m.rtt }
func (m *mockRTTStats) UpdateRTT(sendDelta, ackDelay time.Duration) {}
func (m *mockRTTStats) SetMaxAckDelay(mad time.Duration)           {}
func (m *mockRTTStats) SetInitialRTT(t time.Duration)              {}

func TestBrutalSenderCongestionControlEx(t *testing.T) {
	var cc any = NewBrutalSender(10*1024*1024, 1252, false, nil) // 10 MB/s

	// 1. Verify that BrutalSender implements CongestionControlEx
	ccEx, ok := cc.(congestion.CongestionControlEx)
	if !ok {
		t.Fatal("BrutalSender must implement CongestionControlEx")
	}

	bs := cc.(*BrutalSender)
	bs.SetRTTStatsProvider(&mockRTTStats{rtt: 50 * time.Millisecond})

	// Initial cwnd check
	// cwnd = bps * rtt * multiplier / ackRate
	// 10MB/s * 0.05s * 4 / 1.0 = 2097152 bytes
	initialCwnd := bs.GetCongestionWindow()
	expectedInitial := congestion.ByteCount(2097152)
	if initialCwnd != expectedInitial {
		t.Fatalf("expected initial cwnd %d, got %d", expectedInitial, initialCwnd)
	}

	// 2. Simulate OnCongestionEventEx with 80 acks and 20 losses
	acked := make([]congestion.AckedPacketInfo, 80)
	lost := make([]congestion.LostPacketInfo, 20)
	ccEx.OnCongestionEventEx(1000, monotime.Now(), acked, lost)

	// ackRate should be 80 / 100 = 0.8
	if math.Abs(bs.ackRate-0.8) > 0.001 {
		t.Fatalf("expected ackRate 0.8, got %f", bs.ackRate)
	}

	// cwnd should now expand: 2097152 / 0.8 = 2621440 bytes
	newCwnd := bs.GetCongestionWindow()
	expectedNew := congestion.ByteCount(2621440)
	if newCwnd != expectedNew {
		t.Fatalf("expected new cwnd %d, got %d", expectedNew, newCwnd)
	}

	// 3. Verify other methods don't panic
	ccEx.OnPacketsLost(10)
	ccEx.OnAppLimited(500)
}
