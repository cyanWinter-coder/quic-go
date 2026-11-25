package congestion

import (
	"math"
	"math/bits"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

const maxBurstSizePackets = 10

// minPacingDelay is the minimum duration that is used for packet pacing
// If the packet packing frequency is higher, multiple packets might be sent at once.
// Example: For a packet pacing delay of 200μs, we would send 5 packets at once, wait for 1ms, and so forth.
const minPacingDelay = time.Millisecond

// maxBurstFactor limits the burst released by a single Budget call
// to twice the maximum burst size.
const maxBurstFactor = 2

// The pacer implements a token bucket pacing algorithm.
type pacer struct {
	budgetAtLastSent protocol.ByteCount
	// rateAtLastSent is the pacing rate that budgetAtLastSent was accumulated at.
	// When the rate changes (e.g. because the congestion window was reduced),
	// the leftover budget is rescaled instead of being consumed at the stale rate.
	rateAtLastSent  bandwidth
	maxDatagramSize protocol.ByteCount
	lastSentTime    monotime.Time
}

func newPacer(maxDatagramSize protocol.ByteCount) *pacer {
	return &pacer{
		maxDatagramSize: maxDatagramSize,
	}
}

func (p *pacer) SentPacket(sendTime monotime.Time, size protocol.ByteCount, rate bandwidth) {
	budget := p.Budget(sendTime, rate)
	if size >= budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
	p.rateAtLastSent = rate
}

func (p *pacer) Budget(now monotime.Time, rate bandwidth) protocol.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize(rate)
	}
	maxBurst := p.maxBurstSize(rate)
	var added protocol.ByteCount
	if delta := now.Sub(p.lastSentTime); delta > 0 {
		added = p.timeScaledBandwidth(delta, rate)
		// The connection was idle for long enough to accumulate a full burst.
		// Don't accumulate credit for the idle period: rebuild the budget from
		// the current bandwidth estimate, and release a single maximum burst.
		if added >= maxBurst {
			return maxBurst
		}
	}
	leftover := p.rescaledBudget(rate)
	budget := leftover + added
	if budget < leftover { // overflow
		budget = protocol.MaxByteCount
	}
	// A single burst is limited to twice the maximum burst size.
	return min(maxBurstFactor*maxBurst, budget)
}

// rescaledBudget returns the leftover budget from the last send, converted to
// the current pacing rate. When the bandwidth estimate changes (e.g. because
// the congestion window was cut), the new budget takes effect immediately,
// instead of consuming the budget that was accumulated at the stale rate.
func (p *pacer) rescaledBudget(rate bandwidth) protocol.ByteCount {
	if p.budgetAtLastSent <= 0 || p.rateAtLastSent <= 0 || p.rateAtLastSent == rate {
		return p.budgetAtLastSent
	}
	// budget * rate / rateAtLastSent, with saturation on overflow.
	// The result is capped by the burst limit in Budget, so saturating is fine.
	hi, lo := bits.Mul64(uint64(p.budgetAtLastSent), uint64(rate))
	if hi >= uint64(p.rateAtLastSent) {
		return protocol.MaxByteCount
	}
	q, _ := bits.Div64(hi, lo, uint64(p.rateAtLastSent))
	if q > math.MaxInt64 {
		return protocol.MaxByteCount
	}
	return protocol.ByteCount(q)
}

func (p *pacer) maxBurstSize(rate bandwidth) protocol.ByteCount {
	return max(
		p.timeScaledBandwidth(minPacingDelay+protocol.TimerGranularity, rate),
		maxBurstSizePackets*p.maxDatagramSize,
	)
}

// timeScaledBandwidth calculates the number of bytes that may be sent within
// a given duration, based on the current pacing rate.
// It caps the scaled value to the maximum allowed burst and handles overflows.
func (p *pacer) timeScaledBandwidth(d time.Duration, rate bandwidth) protocol.ByteCount {
	bw := uint64(rate / bytesPerSecond)
	if bw == 0 {
		return 0
	}
	const nsPerSecond = 1e9
	ns := uint64(d)
	maxBurst := maxBurstSizePackets * p.maxDatagramSize
	var scaled protocol.ByteCount
	if ns > math.MaxUint64/bw {
		scaled = maxBurst
	} else {
		scaled = protocol.ByteCount(bw * ns / nsPerSecond)
	}
	return scaled
}

// pacingDelay returns how long the caller needs to wait before sending the
// next packet, measured from the time the last packet was sent.
// It returns 0 if a packet can be sent immediately.
func (p *pacer) pacingDelay(rate bandwidth) time.Duration {
	budget := p.Budget(p.lastSentTime, rate)
	if budget >= p.maxDatagramSize {
		return 0
	}
	bw := uint64(rate / bytesPerSecond)
	if bw == 0 {
		return minPacingDelay
	}
	diff := 1e9 * uint64(p.maxDatagramSize-budget)
	// We might need to round up this value.
	// Otherwise, we might have a budget (slightly) smaller than the datagram size when the timer expires.
	d := diff / bw
	// this is effectively a math.Ceil, but using only integer math
	if diff%bw > 0 {
		d++
	}
	return max(minPacingDelay, time.Duration(d)*time.Nanosecond)
}

// TimeUntilSend returns when the next packet should be sent.
// It returns zero if a packet can be sent immediately.
func (p *pacer) TimeUntilSend(rate bandwidth) monotime.Time {
	if p.lastSentTime.IsZero() {
		return 0
	}
	if d := p.pacingDelay(rate); d > 0 {
		return p.lastSentTime.Add(d)
	}
	return 0
}

func (p *pacer) SetMaxDatagramSize(s protocol.ByteCount) {
	p.maxDatagramSize = s
}
