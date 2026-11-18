package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"

	"github.com/stretchr/testify/require"
)

func TestMigrationFairnessInactiveAllowsAll(t *testing.T) {
	s := newMigrationFairnessScheduler()
	now := monotime.Now()
	require.False(t, s.Active())
	// Without an ongoing migration, every acquire succeeds regardless of usage.
	for range 100 {
		require.True(t, s.Acquire(0, 1, now))
		s.Observe(0, migrationFairnessBudget)
	}
}

func TestMigrationFairnessDefersStreamExceedingBudget(t *testing.T) {
	s := newMigrationFairnessScheduler()
	now := monotime.Now()
	s.Begin(now)

	const queueLen = 3
	// Stream 0 consumes its entire budget and must then be deferred.
	require.True(t, s.Acquire(0, queueLen, now))
	s.Observe(0, migrationFairnessBudget)
	require.False(t, s.Acquire(0, queueLen, now))
	s.Defer(0)

	// The other streams still get a send opportunity.
	require.True(t, s.Acquire(1, queueLen, now))
	s.Observe(1, migrationFairnessBudget)
	require.True(t, s.Acquire(2, queueLen, now))
	s.Observe(2, migrationFairnessBudget)

	// Once all queued streams were deferred, a new round starts and stream 0 is allowed again.
	s.Defer(1)
	s.Defer(2)
	require.True(t, s.Acquire(0, queueLen, now))
	require.Zero(t, s.sent[0])
}

func TestMigrationFairnessPartialUsageDoesNotDefer(t *testing.T) {
	s := newMigrationFairnessScheduler()
	now := monotime.Now()
	s.Begin(now)

	// Streams that send less than the budget keep being scheduled.
	for range 10 {
		require.True(t, s.Acquire(4, 2, now))
		s.Observe(4, 100) // well below the budget
	}

	s.End()
	require.False(t, s.Active())
	require.Empty(t, s.sent)
}

func TestMigrationFairnessRestartsRoundOnQueueChange(t *testing.T) {
	s := newMigrationFairnessScheduler()
	now := monotime.Now()
	s.Begin(now)

	require.True(t, s.Acquire(0, 2, now))
	s.Observe(0, migrationFairnessBudget)
	require.False(t, s.Acquire(0, 2, now))
	s.Defer(0)

	// A new stream joins the queue: the round restarts and stream 0 gets a fresh budget.
	require.True(t, s.Acquire(0, 3, now))
	require.Zero(t, s.sent[0])
}

func TestMigrationFairnessAutoExpires(t *testing.T) {
	s := newMigrationFairnessScheduler()
	now := monotime.Now()
	s.Begin(now)
	require.True(t, s.Active())

	later := now.Add(migrationFairnessMaxDuration)
	// After expiry, Acquire no longer restricts any stream.
	require.True(t, s.Acquire(0, 1, later))
	require.False(t, s.Active())
}
