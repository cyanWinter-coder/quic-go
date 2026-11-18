package quic

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// migrationFairnessBudget is the maximum number of bytes a single stream may
// send within one scheduling round while a connection migration is in progress.
// It is sized to cover a few full-size STREAM frames, so that a large stream can
// still make efficient use of a packet's congestion window without starving the
// other streams for multiple packets.
const migrationFairnessBudget protocol.ByteCount = 4 * protocol.InitialPacketSize

// migrationFairnessMaxDuration bounds how long fairness scheduling remains
// active if the migration completion signal is missed.
const migrationFairnessMaxDuration = 5 * time.Second

// migrationFairnessScheduler enforces per-stream send-opportunity fairness while
// a connection migration is in progress.
//
// During a migration the congestion window is reset to its initial value, so the
// connection is briefly limited to a small number of in-flight packets. Without
// per-stream accounting, a single large stream can fill the entire window on
// every packet. The scheduler tracks the bytes each stream was granted within
// the current round; streams that exhausted their budget are deferred until
// every active stream has had a turn (or exhausted its own budget).
//
// It is not safe for concurrent use; the framer holds its mutex.
type migrationFairnessScheduler struct {
	active          bool
	startedAt       monotime.Time
	sent            map[protocol.StreamID]protocol.ByteCount
	deferredStreams map[protocol.StreamID]struct{}
	deferQueueLen   int
}

func newMigrationFairnessScheduler() *migrationFairnessScheduler {
	return &migrationFairnessScheduler{
		sent:            make(map[protocol.StreamID]protocol.ByteCount),
		deferredStreams: make(map[protocol.StreamID]struct{}),
	}
}

// Begin starts a fairness round for a migration.
// It is safe to call repeatedly while a migration is ongoing.
func (s *migrationFairnessScheduler) Begin(now monotime.Time) {
	if s.active {
		return
	}
	s.active = true
	s.startedAt = now
	clear(s.sent)
	clear(s.deferredStreams)
	s.deferQueueLen = 0
}

// End stops fairness scheduling.
func (s *migrationFairnessScheduler) End() {
	s.active = false
	clear(s.sent)
	clear(s.deferredStreams)
	s.deferQueueLen = 0
}

func (s *migrationFairnessScheduler) isActive(now monotime.Time) bool {
	if !s.active {
		return false
	}
	if now.Sub(s.startedAt) >= migrationFairnessMaxDuration {
		s.End()
		return false
	}
	return true
}

// Acquire reports whether the stream is allowed to send right now.
// queueLen is the number of streams currently queued in the scheduling ring.
// A deferred stream has used up its budget for the current round and is
// skipped until the round completes and a new round starts.
func (s *migrationFairnessScheduler) Acquire(id protocol.StreamID, queueLen int, now monotime.Time) bool {
	if !s.isActive(now) {
		return true
	}
	if s.deferQueueLen != queueLen {
		// Streams were added or removed; restart the round so every queued stream
		// gets a fresh turn within the new queue.
		clear(s.sent)
		clear(s.deferredStreams)
		s.deferQueueLen = queueLen
	}
	if len(s.deferredStreams) >= queueLen {
		// Every queued stream was deferred at least once: start a new round.
		clear(s.sent)
		clear(s.deferredStreams)
	}
	if s.sent[id] >= migrationFairnessBudget {
		return false
	}
	return true
}

// Defer records that a stream was skipped because it exhausted its budget.
func (s *migrationFairnessScheduler) Defer(id protocol.StreamID) {
	s.sent[id] = migrationFairnessBudget
	s.deferredStreams[id] = struct{}{}
}

// Observe records the number of bytes granted to a stream.
func (s *migrationFairnessScheduler) Observe(id protocol.StreamID, n protocol.ByteCount) {
	if !s.active || n == 0 {
		return
	}
	s.sent[id] += n
}

// Active reports whether fairness scheduling is currently enabled.
func (s *migrationFairnessScheduler) Active() bool { return s.active }
