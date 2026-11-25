package quic

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

type uid510SeqConnIDGenerator struct {
	next atomic.Uint64
}

func (g *uid510SeqConnIDGenerator) GenerateConnectionID() (protocol.ConnectionID, error) {
	seq := g.next.Add(1)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], seq)
	return protocol.ParseConnectionID(b[:]), nil
}

func (g *uid510SeqConnIDGenerator) ConnectionIDLen() int { return 8 }

type uid510FrameCollector struct {
	mu     sync.Mutex
	frames []wire.Frame
}

func (c *uid510FrameCollector) add(f wire.Frame) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frames = append(c.frames, f)
}

func (c *uid510FrameCollector) snapshot() []wire.Frame {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]wire.Frame(nil), c.frames...)
}

func (c *uid510FrameCollector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frames = nil
}

func uid510CID(b byte) protocol.ConnectionID {
	return protocol.ParseConnectionID([]byte{b, b, b, b, b, b, b, b})
}

func TestUID510ConnIDGeneratorLifecycle(t *testing.T) {
	var tracker connIDTracker
	frames := &uid510FrameCollector{}
	g := newConnIDGenerator(
		&tracker,
		uid510CID(1),
		uid510CID(2),
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		&pathReceiver{},
		frames.add,
		&protocol.DefaultConnectionIDGenerator{ConnLen: 8},
	)

	require.NoError(t, g.SetMaxActiveConnIDs(4))
	issued := frames.snapshot()
	require.Len(t, issued, 3)
	connID1 := issued[0].(*wire.NewConnectionIDFrame).ConnectionID
	connID2 := issued[1].(*wire.NewConnectionIDFrame).ConnectionID
	connID3 := issued[2].(*wire.NewConnectionIDFrame).ConnectionID

	now := monotime.Now()
	retireAt := now.Add(time.Minute)

	// Retiring is idempotent, but only creates one grace-period entry.
	require.NoError(t, g.Retire(2, uid510CID(9), retireAt))
	require.NoError(t, g.Retire(2, uid510CID(9), retireAt.Add(time.Second)))
	require.Len(t, g.connIDsToRetire, 1)
	require.Equal(t, retireAt, g.NextRetireTime())

	// The retired ID can still receive packets until the grace period ends.
	require.NoError(t, g.CheckReceivedConnectionID(connID2))
	g.RemoveRetiredConnIDs(retireAt.Add(-time.Millisecond))
	require.Empty(t, tracker.removed)

	g.RemoveRetiredConnIDs(retireAt)
	require.Equal(t, []protocol.ConnectionID{connID2}, tracker.removed)
	require.Empty(t, g.connIDsToRetire)
	require.Zero(t, g.NextRetireTime())
	err := g.CheckReceivedConnectionID(connID2)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})

	// Completely unknown IDs are rejected as well.
	err = g.CheckReceivedConnectionID(uid510CID(0x42))
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})

	// A future sequence number has not been issued yet.
	err = g.Retire(g.highestSeq+1, uid510CID(9), now)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "highest issued")

	// A RETIRE_CONNECTION_ID frame cannot retire the connection ID of its own packet.
	before := len(g.connIDsToRetire)
	err = g.Retire(3, connID3, now)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "was used as the Destination Connection ID on this packet")
	require.Len(t, g.connIDsToRetire, before)
	require.Contains(t, g.activeSrcConnIDs, uint64(3))

	// The replacement for seq 2 uses the next monotonic sequence number.
	allFrames := frames.snapshot()
	require.EqualValues(t, 4, allFrames[len(allFrames)-1].(*wire.NewConnectionIDFrame).SequenceNumber)
	require.EqualValues(t, 4, g.highestSeq)
	require.NotEqual(t, connID1, connID2)
}

func TestUID510ConnIDGeneratorConcurrentAllocRetire(t *testing.T) {
	var tracker connIDTracker
	frames := &uid510FrameCollector{}
	g := newConnIDGenerator(
		&tracker,
		uid510CID(1),
		protocol.ConnectionID{},
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		&pathReceiver{},
		frames.add,
		&uid510SeqConnIDGenerator{},
	)

	require.NoError(t, g.SetMaxActiveConnIDs(1000))
	for range 45 {
		require.NoError(t, g.issueNewConnID())
	}
	require.EqualValues(t, 50, g.highestSeq)
	frames.reset()
	tracker.added = nil

	const directAllocations = 50
	var wg sync.WaitGroup
	errs := make(chan error, 2*51+directAllocations)

	// Retire every initially present sequence number twice concurrently.
	for seq := range uint64(51) {
		for range 2 {
			wg.Add(1)
			go func(seq uint64) {
				defer wg.Done()
				errs <- g.Retire(seq, uid510CID(0x7f), monotime.Now())
			}(seq)
		}
	}
	for range directAllocations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- g.issueNewConnID()
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	// 51 successful retirements atomically issue one replacement each, and the direct
	// allocations add the remaining sequence numbers.
	const expectedHighest = 50 + 51 + directAllocations
	require.EqualValues(t, expectedHighest, g.highestSeq)
	issued := frames.snapshot()
	require.Len(t, issued, 51+directAllocations)
	for i, f := range issued {
		ncid, ok := f.(*wire.NewConnectionIDFrame)
		require.True(t, ok)
		require.EqualValues(t, 51+i, ncid.SequenceNumber)
	}
	require.Len(t, g.activeSrcConnIDs, 51+directAllocations)
	require.Len(t, tracker.added, 51+directAllocations)
	require.Len(t, g.connIDsToRetire, 51)

	// Expiry removes every retired ID exactly once.
	g.RemoveRetiredConnIDs(monotime.Now().Add(time.Hour))
	require.Len(t, tracker.removed, 51)
	require.Empty(t, g.connIDsToRetire)
	seen := make(map[protocol.ConnectionID]struct{}, len(tracker.removed))
	for _, id := range tracker.removed {
		_, duplicate := seen[id]
		require.False(t, duplicate)
		seen[id] = struct{}{}
	}

	// RemoveAll releases all active entries and is idempotent.
	g.RemoveAll()
	removedAfterClose := len(tracker.removed)
	require.Len(t, tracker.removed, 51+51+directAllocations)
	g.RemoveAll()
	require.Len(t, tracker.removed, removedAfterClose)
}

type uid510RejectAddRunner struct {
	*connIDTracker
}

func (r *uid510RejectAddRunner) Add(protocol.ConnectionID, packetHandler) bool { return false }

func TestUID510ConnIDGeneratorRejectsUnregisteredID(t *testing.T) {
	runner := &uid510RejectAddRunner{connIDTracker: &connIDTracker{}}
	frames := &uid510FrameCollector{}
	g := newConnIDGenerator(
		runner,
		uid510CID(1),
		protocol.ConnectionID{},
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		&pathReceiver{},
		frames.add,
		&uid510SeqConnIDGenerator{},
	)

	err := g.issueNewConnID()
	require.Error(t, err)
	require.Empty(t, frames.snapshot())
	require.EqualValues(t, 0, g.highestSeq)
	require.Len(t, g.activeSrcConnIDs, 1)
}

func TestUID510ConnIDManagerMigrationRetirement(t *testing.T) {
	frames := &uid510FrameCollector{}
	m := newConnIDManager(
		uid510CID(0),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		frames.add,
	)

	cid1 := uid510CID(1)
	cid2 := uid510CID(2)
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: cid1}))
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{SequenceNumber: 2, ConnectionID: cid2}))

	id1, ok := m.GetConnIDForPath(1)
	require.True(t, ok)
	require.Equal(t, cid1, id1)
	id2, ok := m.GetConnIDForPath(2)
	require.True(t, ok)
	require.Equal(t, cid2, id2)

	m.SwitchToPath(1)
	require.Equal(t, cid1, m.Get())
	m.SwitchToPath(2)
	require.Equal(t, cid2, m.Get())

	// The old path entries are gone. Duplicate and unknown retirements are no-ops.
	m.RetireConnIDForPath(1)
	m.RetireConnIDForPath(2)
	m.RetireConnIDForPath(pathID(99))
	_, ok = m.GetConnIDForPath(1)
	require.False(t, ok)

	// Switching back without an allocated path ID and without a queued ID keeps the active ID.
	m.SwitchToPath(1)
	require.Equal(t, cid2, m.Get())

	require.Equal(t, []wire.Frame{
		&wire.RetireConnectionIDFrame{SequenceNumber: 0},
		&wire.RetireConnectionIDFrame{SequenceNumber: 1},
	}, frames.snapshot())
}

func TestUID510ConnIDManagerConcurrentPathRetire(t *testing.T) {
	var addedTokens, removedTokens, retireFrames atomic.Int64
	m := newConnIDManager(
		uid510CID(0),
		func(protocol.StatelessResetToken) { addedTokens.Add(1) },
		func(protocol.StatelessResetToken) { removedTokens.Add(1) },
		func(f wire.Frame) {
			if _, ok := f.(*wire.RetireConnectionIDFrame); ok {
				retireFrames.Add(1)
			}
		},
	)
	cid1 := uid510CID(1)
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: cid1}))

	const goroutines = 32
	start := make(chan struct{})
	connIDs := make(chan protocol.ConnectionID, goroutines)
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			id, ok := m.GetConnIDForPath(42)
			if ok {
				connIDs <- id
			}
		}()
	}
	close(start)
	wg.Wait()
	close(connIDs)
	for id := range connIDs {
		require.Equal(t, cid1, id)
	}
	require.EqualValues(t, 1, addedTokens.Load())

	startRetire := make(chan struct{})
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startRetire
			m.RetireConnIDForPath(42)
		}()
	}
	close(startRetire)
	wg.Wait()

	require.EqualValues(t, 1, retireFrames.Load())
	require.EqualValues(t, 1, removedTokens.Load())
	_, ok := m.GetConnIDForPath(42)
	require.False(t, ok)
}
