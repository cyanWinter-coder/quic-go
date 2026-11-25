package quic

import (
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

// The memory address of the Transport is used as the key.
// The value is the pathReceiver that the connection's connection IDs are registered with on that Transport.
type connRunners map[connRunner]*pathReceiver

func (cr connRunners) AddConnectionID(id protocol.ConnectionID) bool {
	var added []connRunner
	for r, h := range cr {
		if !r.Add(id, h) {
			// Roll back registrations already made on other Transports.
			for _, addedRunner := range added {
				addedRunner.Remove(id)
			}
			return false
		}
		added = append(added, r)
	}
	return true
}

func (cr connRunners) RemoveConnectionID(id protocol.ConnectionID) {
	for r := range cr {
		r.Remove(id)
	}
}

func (cr connRunners) ReplaceWithClosed(ids []protocol.ConnectionID, b []byte, expiry time.Duration) {
	for r := range cr {
		r.ReplaceWithClosed(ids, b, expiry)
	}
}

type connIDToRetire struct {
	t      monotime.Time
	connID protocol.ConnectionID
}

type connIDGenerator struct {
	mx          sync.Mutex
	generator   ConnectionIDGenerator
	highestSeq  uint64
	connRunners connRunners

	activeSrcConnIDs        map[uint64]protocol.ConnectionID
	connIDsToRetire         []connIDToRetire      // sorted by t
	initialClientDestConnID protocol.ConnectionID // invalid for the client

	statelessResetter *statelessResetter

	queueControlFrame func(wire.Frame)
}

func newConnIDGenerator(
	runner connRunner,
	initialConnectionID protocol.ConnectionID,
	initialClientDestConnID protocol.ConnectionID, // invalid for the client
	statelessResetter *statelessResetter,
	handler *pathReceiver,
	queueControlFrame func(wire.Frame),
	generator ConnectionIDGenerator,
) *connIDGenerator {
	m := &connIDGenerator{
		generator:         generator,
		activeSrcConnIDs:  make(map[uint64]protocol.ConnectionID),
		statelessResetter: statelessResetter,
		connRunners:       connRunners{runner: handler},
		queueControlFrame: queueControlFrame,
	}
	m.activeSrcConnIDs[0] = initialConnectionID
	m.initialClientDestConnID = initialClientDestConnID
	return m
}

func (m *connIDGenerator) SetMaxActiveConnIDs(limit uint64) error {
	m.mx.Lock()
	defer m.mx.Unlock()

	if m.generator.ConnectionIDLen() == 0 {
		return nil
	}
	// The active_connection_id_limit transport parameter is the number of
	// connection IDs the peer will store. This limit includes the connection ID
	// used during the handshake, and the one sent in the preferred_address
	// transport parameter.
	// We currently don't send the preferred_address transport parameter,
	// so we can issue (limit - 1) connection IDs.
	for i := uint64(len(m.activeSrcConnIDs)); i < min(limit, protocol.MaxIssuedConnectionIDs); i++ {
		if err := m.issueNewConnIDLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (m *connIDGenerator) Retire(seq uint64, sentWithDestConnID protocol.ConnectionID, expiry monotime.Time) error {
	m.mx.Lock()
	defer m.mx.Unlock()

	if seq > m.highestSeq {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d (highest issued: %d)", seq, m.highestSeq),
		}
	}
	connID, ok := m.activeSrcConnIDs[seq]
	// We might already have deleted this connection ID, if this is a duplicate frame.
	if !ok {
		return nil
	}
	if connID == sentWithDestConnID {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d (%s), which was used as the Destination Connection ID on this packet", seq, connID),
		}
	}
	m.queueConnIDForRetiringLocked(connID, expiry)

	delete(m.activeSrcConnIDs, seq)
	return m.issueNewConnIDLocked()
}

func (m *connIDGenerator) queueConnIDForRetiring(connID protocol.ConnectionID, expiry monotime.Time) {
	m.mx.Lock()
	defer m.mx.Unlock()
	m.queueConnIDForRetiringLocked(connID, expiry)
}

func (m *connIDGenerator) queueConnIDForRetiringLocked(connID protocol.ConnectionID, expiry monotime.Time) {
	// Retire is idempotent, but defend against duplicate bookkeeping entries.
	if slices.ContainsFunc(m.connIDsToRetire, func(c connIDToRetire) bool {
		return c.connID == connID
	}) {
		return
	}
	idx := slices.IndexFunc(m.connIDsToRetire, func(c connIDToRetire) bool {
		return c.t.After(expiry)
	})
	if idx == -1 {
		idx = len(m.connIDsToRetire)
	}
	m.connIDsToRetire = slices.Insert(m.connIDsToRetire, idx, connIDToRetire{t: expiry, connID: connID})
}

func (m *connIDGenerator) issueNewConnID() error {
	m.mx.Lock()
	defer m.mx.Unlock()
	return m.issueNewConnIDLocked()
}

func (m *connIDGenerator) issueNewConnIDLocked() error {
	seq := m.highestSeq + 1
	if _, ok := m.activeSrcConnIDs[seq]; ok {
		return &qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: fmt.Sprintf("connection ID sequence number %d has already been issued", seq),
		}
	}
	connID, err := m.generator.GenerateConnectionID()
	if err != nil {
		return err
	}
	// Don't advertise an ID that is already registered, e.g. with a Transport that still keeps a
	// recently closed connection's ID for delayed packets.
	if !m.connRunners.AddConnectionID(connID) {
		return &qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: fmt.Sprintf("generated duplicate connection ID %s", connID),
		}
	}
	m.activeSrcConnIDs[seq] = connID
	m.queueControlFrame(&wire.NewConnectionIDFrame{
		SequenceNumber:      seq,
		ConnectionID:        connID,
		StatelessResetToken: m.statelessResetter.GetStatelessResetToken(connID),
	})
	m.highestSeq = seq
	return nil
}

// NextRetireTime returns the earliest time at which a retired connection ID can be removed.
func (m *connIDGenerator) NextRetireTime() monotime.Time {
	m.mx.Lock()
	defer m.mx.Unlock()

	if len(m.connIDsToRetire) == 0 {
		return 0
	}
	return m.connIDsToRetire[0].t
}

// CheckReceivedConnectionID validates that id is still allowed to identify this connection.
// Retired IDs remain valid until their grace period expires and RemoveRetiredConnIDs removes them.
func (m *connIDGenerator) CheckReceivedConnectionID(id protocol.ConnectionID) error {
	m.mx.Lock()
	defer m.mx.Unlock()

	// Zero-length connection IDs are shared by all packets and have no retirement state.
	if m.generator.ConnectionIDLen() == 0 {
		return nil
	}
	if m.initialClientDestConnID.Valid() && m.initialClientDestConnID == id {
		return nil
	}
	for _, connID := range m.activeSrcConnIDs {
		if connID == id {
			return nil
		}
	}
	if slices.ContainsFunc(m.connIDsToRetire, func(c connIDToRetire) bool {
		return c.connID == id
	}) {
		return nil
	}
	return &qerr.TransportError{
		ErrorCode:    qerr.ProtocolViolation,
		ErrorMessage: fmt.Sprintf("received packet for retired or unknown connection ID %s", id),
	}
}

func (m *connIDGenerator) SetHandshakeComplete(connIDExpiry monotime.Time) {
	m.mx.Lock()
	defer m.mx.Unlock()

	if m.initialClientDestConnID.Valid() {
		m.queueConnIDForRetiringLocked(m.initialClientDestConnID, connIDExpiry)
		m.initialClientDestConnID = protocol.ConnectionID{}
	}
}

// IsInitialClientDestConnID reports whether the connection ID is the one the client used on its Initial packets.
// It returns false on the client, and once the handshake is complete.
func (m *connIDGenerator) IsInitialClientDestConnID(id protocol.ConnectionID) bool {
	m.mx.Lock()
	defer m.mx.Unlock()

	return m.initialClientDestConnID.Valid() && m.initialClientDestConnID == id
}

func (m *connIDGenerator) RemoveRetiredConnIDs(now monotime.Time) {
	m.mx.Lock()
	defer m.mx.Unlock()

	if len(m.connIDsToRetire) == 0 {
		return
	}
	remaining := m.connIDsToRetire
	for len(remaining) > 0 && !remaining[0].t.After(now) {
		c := remaining[0]
		remaining = remaining[1:]
		m.connRunners.RemoveConnectionID(c.connID)
	}
	m.connIDsToRetire = remaining
}

func (m *connIDGenerator) RemoveAll() {
	m.mx.Lock()
	defer m.mx.Unlock()

	if m.initialClientDestConnID.Valid() {
		m.connRunners.RemoveConnectionID(m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		m.connRunners.RemoveConnectionID(connID)
	}
	for _, c := range m.connIDsToRetire {
		m.connRunners.RemoveConnectionID(c.connID)
	}
	m.initialClientDestConnID = protocol.ConnectionID{}
	clear(m.activeSrcConnIDs)
	m.connIDsToRetire = nil
}

func (m *connIDGenerator) ReplaceWithClosed(connClose []byte, expiry time.Duration) {
	m.mx.Lock()
	defer m.mx.Unlock()

	connIDs := make([]protocol.ConnectionID, 0, len(m.activeSrcConnIDs)+len(m.connIDsToRetire)+1)
	if m.initialClientDestConnID.Valid() {
		connIDs = append(connIDs, m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		connIDs = append(connIDs, connID)
	}
	for _, c := range m.connIDsToRetire {
		connIDs = append(connIDs, c.connID)
	}
	m.connRunners.ReplaceWithClosed(connIDs, connClose, expiry)
}

// Handler returns the pathReceiver that the connection IDs are registered with on the transport.
func (m *connIDGenerator) Handler(runner connRunner) (*pathReceiver, bool) {
	m.mx.Lock()
	defer m.mx.Unlock()

	h, ok := m.connRunners[runner]
	return h, ok
}

// AddConnRunner registers all connection IDs with the pathReceiver on the transport.
// It returns false if the transport was already added.
func (m *connIDGenerator) AddConnRunner(runner connRunner, h *pathReceiver) bool {
	m.mx.Lock()
	defer m.mx.Unlock()

	// The transport might have already been added earlier.
	// This happens for every PATH_CHALLENGE sent on the transport after the first one (including retransmissions),
	// and if the application migrates back to an old path.
	if _, ok := m.connRunners[runner]; ok {
		return false
	}
	m.connRunners[runner] = h
	if m.initialClientDestConnID.Valid() {
		runner.Add(m.initialClientDestConnID, h)
	}
	for _, connID := range m.activeSrcConnIDs {
		runner.Add(connID, h)
	}
	return true
}
