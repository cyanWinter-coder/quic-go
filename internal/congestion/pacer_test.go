package congestion

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"

	"github.com/stretchr/testify/require"
)

func TestPacerPacing(t *testing.T) {
	rate := 50 * bandwidth(initialMaxDatagramSize) * bytesPerSecond // 50 full-size packets per second
	p := newPacer(initialMaxDatagramSize)
	now := monotime.Now()
	require.Zero(t, p.TimeUntilSend(rate))
	budget := p.Budget(now, rate)
	require.Equal(t, maxBurstSizePackets*initialMaxDatagramSize, budget)

	// consume the initial budget by sending packets
	for budget > 0 {
		require.Zero(t, p.TimeUntilSend(rate))
		require.Equal(t, budget, p.Budget(now, rate))
		p.SentPacket(now, initialMaxDatagramSize, rate)
		budget -= initialMaxDatagramSize
	}

	// now packets are being paced
	for range 5 {
		require.Zero(t, p.Budget(now, rate))
		nextPacket := p.TimeUntilSend(rate)
		require.NotZero(t, nextPacket)
		require.Equal(t, time.Second/50, nextPacket.Sub(now))
		now = nextPacket
		p.SentPacket(now, initialMaxDatagramSize, rate)
	}

	nextPacket := p.TimeUntilSend(rate)
	require.Equal(t, time.Second/50, nextPacket.Sub(now))
	// send this packet a bit later, simulating timer delay
	p.SentPacket(nextPacket.Add(time.Millisecond), initialMaxDatagramSize, rate)
	// the next packet should be paced again, without a delay
	require.Equal(t, time.Second/50, p.TimeUntilSend(rate).Sub(nextPacket))

	// now send a half-size packet
	now = p.TimeUntilSend(rate)
	p.SentPacket(now, initialMaxDatagramSize/2, rate)
	require.Equal(t, initialMaxDatagramSize/2, p.Budget(now, rate))
	require.Equal(t, time.Second/100, p.TimeUntilSend(rate).Sub(now))
	p.SentPacket(p.TimeUntilSend(rate), initialMaxDatagramSize/2, rate)

	now = p.TimeUntilSend(rate)
	// budget accumulates if no packets are sent for a while
	// we should have accumulated budget to send a burst now
	require.Equal(t, 5*initialMaxDatagramSize, p.Budget(now.Add(4*time.Second/50), rate))
	// but the budget is capped at the max burst size
	require.Equal(t, maxBurstSizePackets*initialMaxDatagramSize, p.Budget(now.Add(time.Hour), rate))
	p.SentPacket(now, initialMaxDatagramSize, rate)
	require.Zero(t, p.Budget(now, rate))

	// reduce the rate
	rate = 10 * bandwidth(initialMaxDatagramSize) * bytesPerSecond // 10 full-size packets per second
	require.Equal(t, time.Second/10, p.TimeUntilSend(rate).Sub(now))
}

func TestPacerUpdatePacketSize(t *testing.T) {
	const rate = 50 * bandwidth(initialMaxDatagramSize) * bytesPerSecond // 50 full-size packets per second
	p := newPacer(initialMaxDatagramSize)

	// consume the initial budget by sending packets
	now := monotime.Now()
	for p.Budget(now, rate) > 0 {
		p.SentPacket(now, initialMaxDatagramSize, rate)
	}

	require.Equal(t, time.Second/50, p.TimeUntilSend(rate).Sub(now))
	// Double the packet size. We now need to wait twice as long to send the next packet.
	const newDatagramSize = 2 * initialMaxDatagramSize
	p.SetMaxDatagramSize(newDatagramSize)
	require.Equal(t, 2*time.Second/50, p.TimeUntilSend(rate).Sub(now))

	// check that the maximum burst size is updated
	require.Equal(t, maxBurstSizePackets*newDatagramSize, p.Budget(now.Add(time.Hour), rate))
}

func TestPacerFastPacing(t *testing.T) {
	const rate = 10000 * bandwidth(initialMaxDatagramSize) * bytesPerSecond // 10,000 full-size packets per second
	p := newPacer(initialMaxDatagramSize)

	// consume the initial budget by sending packets
	now := monotime.Now()
	for p.Budget(now, rate) > 0 {
		p.SentPacket(now, initialMaxDatagramSize, rate)
	}

	// If we were pacing by packet, we'd expect the next packet to send in 1/10ms.
	// However, we don't want to arm the pacing timer for less than 1ms,
	// so we wait for 1ms, and then send 10 packets in a burst.
	require.Equal(t, time.Millisecond, p.TimeUntilSend(rate).Sub(now))
	require.Equal(t, 10*initialMaxDatagramSize, p.Budget(now.Add(time.Millisecond), rate))

	now = now.Add(time.Millisecond)
	for range 10 {
		require.NotZero(t, p.Budget(now, rate))
		p.SentPacket(now, initialMaxDatagramSize, rate)
	}
	require.Zero(t, p.Budget(now, rate))
	require.Equal(t, time.Millisecond, p.TimeUntilSend(rate).Sub(now))
}

func TestPacerNoOverflows(t *testing.T) {
	const rate bandwidth = math.MaxUint64
	p := newPacer(initialMaxDatagramSize)
	now := monotime.Now()
	p.SentPacket(now, initialMaxDatagramSize, rate)
	for range 100000 {
		require.NotZero(t, p.Budget(now.Add(time.Duration(rand.Int64N(math.MaxInt64))), rate))
	}

	burstCount := 1
	for p.Budget(now, rate) > 0 {
		burstCount++
		p.SentPacket(now, initialMaxDatagramSize, rate)
	}
	require.Equal(t, maxBurstSizePackets, burstCount)
	require.Zero(t, p.Budget(now, rate))

	next := p.TimeUntilSend(rate)
	require.Equal(t, next.Sub(now), minPacingDelay)
	require.Greater(t, p.Budget(next, rate), initialMaxDatagramSize)
}

// After an idle period, the budget is rebuilt from the current bandwidth
// estimate: a single maximum burst is released, without accumulating credit
// for the idle period or carrying over the leftover budget.
func TestPacerIdleResume(t *testing.T) {
	// Use a rate high enough that the max burst is determined by the pacing
	// delay, not by the packet count: 10,000 packets/s * 2ms = 20 packets.
	const rate = 10000 * bandwidth(initialMaxDatagramSize) * bytesPerSecond
	p := newPacer(initialMaxDatagramSize)
	now := monotime.Now()
	maxBurst := p.maxBurstSize(rate)
	require.Equal(t, 20*initialMaxDatagramSize, maxBurst)

	// consume half of the budget
	p.SentPacket(now, maxBurst/2, rate)
	require.Equal(t, maxBurst/2, p.Budget(now, rate))

	// idle for a long time
	now = now.Add(time.Minute)
	// The budget is rebuilt from the current bandwidth estimate.
	// It is a single maximum burst: the leftover budget is discarded,
	// and no credit is accumulated for the idle period.
	require.Equal(t, maxBurst, p.Budget(now, rate))

	// The rebuilt budget uses the bandwidth estimate at resume time,
	// not the estimate from before the idle period.
	const halfRate = rate / 2
	require.Equal(t, p.maxBurstSize(halfRate), p.Budget(now, halfRate))

	// sending after the idle period consumes from the rebuilt budget
	p.SentPacket(now, initialMaxDatagramSize, rate)
	require.Equal(t, maxBurst-initialMaxDatagramSize, p.Budget(now, rate))
}

// The burst released by a single Budget call never exceeds twice the maximum
// burst size, no matter how much budget was accumulated.
func TestPacerBurstCap(t *testing.T) {
	const rate = 50 * bandwidth(initialMaxDatagramSize) * bytesPerSecond // 50 full-size packets per second
	p := newPacer(initialMaxDatagramSize)
	now := monotime.Now()
	const maxBurst = maxBurstSizePackets * initialMaxDatagramSize

	p.SentPacket(now, initialMaxDatagramSize, rate)
	// Accumulate budget over pauses that are shorter than the idle threshold
	// (200ms at this rate): each 150ms pause accumulates 7.5 packets.
	for i := range 10 {
		now = now.Add(150 * time.Millisecond)
		p.SentPacket(now, 1, rate) // send a tiny packet to keep most of the budget
		if i == 0 {
			// budget accumulates beyond a single max burst...
			require.Greater(t, p.Budget(now, rate), maxBurst)
		}
	}
	// ...but a single release never exceeds twice the max burst size.
	require.Equal(t, 2*maxBurst, p.Budget(now.Add(150*time.Millisecond), rate))
}

// When the congestion window shrinks, the pacing rate drops and the leftover
// budget shrinks proportionally: we don't keep sending at the old rate.
func TestPacerWindowShrink(t *testing.T) {
	const rate = 100 * bandwidth(initialMaxDatagramSize) * bytesPerSecond // 100 full-size packets per second
	p := newPacer(initialMaxDatagramSize)
	now := monotime.Now()

	// consume one packet, leaving 9 packets of budget
	p.SentPacket(now, initialMaxDatagramSize, rate)
	require.Equal(t, 9*initialMaxDatagramSize, p.Budget(now, rate))

	// The congestion window is cut in half, halving the pacing rate.
	// The leftover budget shrinks proportionally, effective immediately.
	const newRate = rate / 2
	require.Equal(t, 9*initialMaxDatagramSize/2, p.Budget(now, newRate))

	// sending consumes from the shrunken budget
	p.SentPacket(now, initialMaxDatagramSize, newRate)
	require.Equal(t, 9*initialMaxDatagramSize/2-initialMaxDatagramSize, p.Budget(now, newRate))

	// drain the budget
	for p.Budget(now, newRate) > 0 {
		p.SentPacket(now, initialMaxDatagramSize, newRate)
	}
	// The pacing delay is based on the new (halved) rate of 50 packets/s,
	// not the old rate of 100 packets/s.
	require.Equal(t, time.Second/50, p.TimeUntilSend(newRate).Sub(now))
}

// When the bandwidth estimate increases, the new budget takes effect
// immediately: the leftover budget is rescaled, and the budget accumulated at
// the old rate is not consumed as-is.
func TestPacerBandwidthIncrease(t *testing.T) {
	const rate = 50 * bandwidth(initialMaxDatagramSize) * bytesPerSecond // 50 full-size packets per second
	p := newPacer(initialMaxDatagramSize)
	now := monotime.Now()

	// consume one packet, leaving 9 packets of budget
	p.SentPacket(now, initialMaxDatagramSize, rate)
	require.Equal(t, 9*initialMaxDatagramSize, p.Budget(now, rate))

	// The bandwidth estimate doubles. The leftover budget is rescaled to the
	// new rate, effective immediately.
	require.Equal(t, 2*9*initialMaxDatagramSize, p.Budget(now, 2*rate))

	// Sending consumes from the rescaled budget, and the new rate is retained:
	// when the estimate drops back, the leftover is converted from the
	// budget tracked at the increased rate, not the original one.
	p.SentPacket(now, initialMaxDatagramSize, 2*rate)
	require.Equal(t, 2*9*initialMaxDatagramSize-initialMaxDatagramSize, p.Budget(now, 2*rate))
	require.Equal(t, (2*9*initialMaxDatagramSize-initialMaxDatagramSize)/2, p.Budget(now, rate))
}

func BenchmarkPacer(b *testing.B) {
	const rate = 50 * bandwidth(initialMaxDatagramSize) * bytesPerSecond // 50 full-size packets per second
	p := newPacer(initialMaxDatagramSize)

	now := monotime.Now()

	var i int
	for b.Loop() {
		i++
		for p.Budget(now, rate) > 0 {
			p.SentPacket(now, initialMaxDatagramSize, rate)
		}
		next := p.TimeUntilSend(rate)
		if i%2 == 0 {
			now = next
		} else {
			now = now.Add(100 * time.Millisecond)
		}
	}
}
