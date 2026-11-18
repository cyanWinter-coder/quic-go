package self_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// pathBlockingRouter drops every packet sent to a blocked destination address.
// It is used to make a probed path unreachable so that path validation fails,
// while leaving the connection's active path fully functional.
type pathBlockingRouter struct {
	simnet.PerfectRouter
	mu      sync.Mutex
	blocked map[string]bool
}

func newPathBlockingRouter() *pathBlockingRouter {
	return &pathBlockingRouter{blocked: make(map[string]bool)}
}

func (r *pathBlockingRouter) Block(addr net.Addr) {
	r.mu.Lock()
	r.blocked[addr.String()] = true
	r.mu.Unlock()
}

func (r *pathBlockingRouter) Unblock(addr net.Addr) {
	r.mu.Lock()
	delete(r.blocked, addr.String())
	r.mu.Unlock()
}

func (r *pathBlockingRouter) SendPacket(p simnet.Packet) error {
	r.mu.Lock()
	blocked := r.blocked[p.To.String()]
	r.mu.Unlock()
	if blocked {
		return nil
	}
	return r.PerfectRouter.SendPacket(p)
}

// newMigrationNetwork creates a simnet using a pathBlockingRouter and returns the
// network together with the router so tests can block individual paths.
func newMigrationNetwork(t *testing.T, rtt time.Duration) (*testNetwork, *pathBlockingRouter) {
	t.Helper()
	router := newPathBlockingRouter()
	n := &testNetwork{
		simnet:   simnet.Simnet{Router: router},
		settings: simnet.NodeBiDiLinkSettings{Latency: rtt / 2},
	}
	t.Cleanup(func() { require.NoError(t, n.Close()) })
	return n, router
}

// streamBytes counts the STREAM bytes sent on each stream from the qlog events.
func streamBytes(t *testing.T, evs []qlogwriter.Event) map[quic.StreamID]uint64 {
	t.Helper()
	sent := make(map[quic.StreamID]uint64)
	for _, ev := range evs {
		e, ok := ev.(qlog.PacketSent)
		if !ok {
			continue
		}
		for _, f := range e.Frames {
			if sf, ok := f.Frame.(*qlog.StreamFrame); ok {
				sent[sf.StreamID] += uint64(sf.Length)
			}
		}
	}
	return sent
}

// TestPathValidationFailureKeepsDataOnOldPath makes sure application data is never
// sent on a path that fails validation, and that the connection keeps working on
// the original path afterwards.
func TestPathValidationFailureKeepsDataOnOldPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond
		network, router := newMigrationNetwork(t, rtt)

		ln, err := quic.Listen(network.NewConn(), getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()

		pc1 := network.NewConn()
		tr1 := &quic.Transport{Conn: pc1}
		defer tr1.Close()
		pc2 := network.NewConn()
		tr2 := &quic.Transport{Conn: pc2}
		defer tr2.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		conn, err := tr1.Dial(ctx, ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		sconn, err := ln.Accept(ctx)
		require.NoError(t, err)
		defer sconn.CloseWithError(0, "")

		// Block the new path entirely. PATH_CHALLENGE packets can't reach the server
		// and no PATH_RESPONSE will ever come back.
		router.Block(pc2.LocalAddr())

		path, err := conn.AddPath(tr2)
		require.NoError(t, err)

		probeErr := make(chan error, 1)
		go func() { probeErr <- path.Probe(ctx) }()

		// While probing fails, application data keeps flowing over the old path.
		time.Sleep(50 * rtt)

		str, err := conn.OpenUniStream()
		require.NoError(t, err)
		go func() {
			sstr, acceptErr := sconn.AcceptUniStream(ctx)
			if acceptErr != nil {
				return
			}
			_, _ = io.Copy(io.Discard, sstr)
		}()
		_, err = str.Write(PRData)
		require.NoError(t, err)
		require.NoError(t, str.Close())

		// Nothing but (undelivered) probes were ever sent on the blocked path.
		// The connection must never have switched to it.
		require.NotEqual(t, tr2.Conn.LocalAddr(), conn.LocalAddr())
		require.Equal(t, tr1.Conn.LocalAddr(), conn.LocalAddr())

		// Wait for the validation timeout (5s) to elapse in virtual time.
		time.Sleep(6 * time.Second)
		synctest.Wait()
		select {
		case err := <-probeErr:
			require.ErrorIs(t, err, quic.ErrPathValidationTimeout)
		case <-time.After(time.Second):
			t.Fatal("probe should have failed with a validation timeout")
		}

		// Switching to the unvalidated path is rejected.
		require.ErrorIs(t, path.Switch(), quic.ErrPathNotValidated)

		// The connection is still fully functional on the original path.
		str2, err := conn.OpenUniStream()
		require.NoError(t, err)
		errChan := make(chan error, 1)
		go func() {
			defer close(errChan)
			sstr, err := sconn.AcceptUniStream(ctx)
			if err != nil {
				errChan <- err
				return
			}
			data, err := io.ReadAll(sstr)
			if err != nil {
				errChan <- err
				return
			}
			if !bytes.Equal(data, PRData) {
				errChan <- errors.New("data mismatch after failed validation")
			}
		}()
		_, err = str2.Write(PRData)
		require.NoError(t, err)
		require.NoError(t, str2.Close())
		select {
		case err := <-errChan:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("stream did not complete on the original path")
		}
	})
}

// TestNATRebindingAntiAmplification verifies that after the client's address changes
// (NAT rebinding), the server re-applies the anti-amplification limit until the new
// address is validated.
func TestNATRebindingAntiAmplification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond
		network, _ := newMigrationNetwork(t, rtt)

		var serverEvents events.Recorder
		ln, err := quic.Listen(
			network.NewConn(),
			getTLSConfig(),
			getQuicConfig(&quic.Config{Tracer: newTracer(&serverEvents)}),
		)
		require.NoError(t, err)
		defer ln.Close()

		// The client uses a single Transport, but its underlying SimConn changes its
		// source address: this is a NAT rebinding rather than an intentional migration.
		pc := network.NewConn()
		tr := &quic.Transport{Conn: pc}
		defer tr.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		conn, err := tr.Dial(ctx, ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		sconn, err := ln.Accept(ctx)
		require.NoError(t, err)
		defer sconn.CloseWithError(0, "")

		// Complete a stream so the connection is fully established and validated.
		str, err := conn.OpenUniStream()
		require.NoError(t, err)
		_, err = str.Write([]byte("handshake data"))
		require.NoError(t, err)
		require.NoError(t, str.Close())
		sstr, err := sconn.AcceptUniStream(ctx)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, sstr)
		require.NoError(t, err)
		synctest.Wait()

		newAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}

		// The client's source address changes: this is a NAT rebinding.
		// SimConn.Rebind unregisters the old address, so packets the server sends to
		// it are no longer delivered, while the new address gets validated via PATH_CHALLENGE.
		require.NoError(t, pc.Rebind(newAddr))

		// Trigger traffic from the new address.
		str2, err := conn.OpenUniStream()
		require.NoError(t, err)
		go func() {
			_, _ = str2.Write(bytes.Repeat([]byte("a"), 50000))
			_ = str2.Close()
		}()

		// Give the server time to observe the new path, probe it, and validate it
		// once the PATH_CHALLENGE/PATH_RESPONSE exchange completes.
		time.Sleep(100 * rtt)

		// The server must have sent PATH_CHALLENGEs on the new (unvalidated) path.
		var sawChallenge bool
		for _, ev := range serverEvents.Events() {
			e, ok := ev.(qlog.PacketSent)
			if !ok {
				continue
			}
			if hasFrame[*qlog.PathChallengeFrame](e.Frames) {
				sawChallenge = true
			}
		}
		require.True(t, sawChallenge, "server should probe the rebinded address")

		// After validation, the connection continues to work and the stream completes.
		sstr2, err := sconn.AcceptUniStream(ctx)
		require.NoError(t, err)
		n, err := io.Copy(io.Discard, sstr2)
		require.NoError(t, err)
		require.EqualValues(t, 50000, n)
	})
}

// TestMigrationFairnessAcrossStreams opens several streams of different sizes and
// triggers an intentional migration, asserting that no single stream monopolizes the
// send opportunities while the migration is in progress.
func TestMigrationFairnessAcrossStreams(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 10 * time.Millisecond
		network := newTestNetworkWithSettings(t, simnet.NodeBiDiLinkSettings{
			Latency: rtt / 2,
			// 1 Mbit/s, so the initial congestion window is the bottleneck during migration
			Uplink:   simnet.LinkSettings{Bandwidth: 1 << 20},
			Downlink: simnet.LinkSettings{Bandwidth: 1 << 20},
		})

		ln, err := quic.Listen(network.NewConn(), getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()

		pc1 := network.NewConn()
		tr1 := &quic.Transport{Conn: pc1}
		defer tr1.Close()
		pc2 := network.NewConn()
		tr2 := &quic.Transport{Conn: pc2}
		defer tr2.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var clientEvents events.Recorder
		conn, err := tr1.Dial(ctx, ln.Addr(), getTLSClientConfig(),
			getQuicConfig(&quic.Config{Tracer: newTracer(&clientEvents)}))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		sconn, err := ln.Accept(ctx)
		require.NoError(t, err)
		defer sconn.CloseWithError(0, "")

		const numStreams = 4
		streamSizes := []int{200000, 50000, 50000, 50000}
		var wg sync.WaitGroup
		for i := range numStreams {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				s, err := conn.OpenUniStream()
				if err != nil {
					return
				}
				_, _ = s.Write(bytes.Repeat([]byte{byte('a' + i)}, streamSizes[i]))
				_ = s.Close()
			}(i)
		}

		// Let the streams ramp up, then migrate while they are still sending.
		time.Sleep(5 * rtt)
		path, err := conn.AddPath(tr2)
		require.NoError(t, err)
		require.NoError(t, path.Probe(ctx))
		migrationStart := len(clientEvents.Events())
		require.NoError(t, path.Switch())
		// Capture the early post-switch window, while the reset congestion window is
		// still small and fairness scheduling is most relevant.
		time.Sleep(20 * rtt)
		earlyWindowEnd := len(clientEvents.Events())

		// Receive all data on the server side.
		for range numStreams {
			s, err := sconn.AcceptUniStream(ctx)
			require.NoError(t, err)
			n, err := io.Copy(io.Discard, s)
			require.NoError(t, err)
			require.Positive(t, n)
		}
		wg.Wait()

		// During the migration window, the small streams must get send opportunities and
		// the largest stream must not capture the whole (reset) congestion window.
		sent := streamBytes(t, clientEvents.Events()[migrationStart:earlyWindowEnd])
		require.Len(t, sent, numStreams)
		var maxShare float64
		var total uint64
		for _, n := range sent {
			total += n
		}
		require.NotZero(t, total)
		for id, n := range sent {
			share := float64(n) / float64(total)
			require.Less(t, share, 0.6,
				fmt.Sprintf("stream %d captured %.0f%% of migration window", id, share*100))
			maxShare = max(maxShare, share)
		}
		require.Less(t, maxShare, 0.6)
	})
}

// TestMigrationThroughputRecovery verifies that after a successful migration the
// sending throughput recovers to at least 80% of the pre-migration level within
// one second. The congestion controller is reset on the new path and ramps back up.
func TestMigrationThroughputRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			bandwidth = 5_000_000 // 5 Mbit/s
			rtt       = 20 * time.Millisecond
			chunk     = 256 << 10
		)
		network := newTestNetworkWithSettings(t, simnet.NodeBiDiLinkSettings{
			Latency:  rtt / 2,
			Uplink:   simnet.LinkSettings{Bandwidth: bandwidth},
			Downlink: simnet.LinkSettings{Bandwidth: bandwidth},
		})

		ln, err := quic.Listen(network.NewConn(), getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()
		pc1 := network.NewConn()
		tr1 := &quic.Transport{Conn: pc1}
		defer tr1.Close()
		pc2 := network.NewConn()
		tr2 := &quic.Transport{Conn: pc2}
		defer tr2.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := tr1.Dial(ctx, ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		sconn, err := ln.Accept(ctx)
		require.NoError(t, err)
		defer sconn.CloseWithError(0, "")

		// drain server streams in the background
		go func() {
			for {
				s, err := sconn.AcceptUniStream(ctx)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, s)
			}
		}()

		measure := func(window time.Duration) uint64 {
			str, err := conn.OpenUniStream()
			require.NoError(t, err)
			start := time.Now()
			var sent uint64
			for time.Since(start) < window {
				n, err := str.Write(make([]byte, chunk))
				require.NoError(t, err)
				sent += uint64(n)
			}
			require.NoError(t, str.Close())
			return sent
		}

		// warm up the connection and measure the steady-state throughput before migration
		measure(200 * rtt)
		before := measure(time.Second)

		// migrate to the second path
		path, err := conn.AddPath(tr2)
		require.NoError(t, err)
		require.NoError(t, path.Probe(ctx))
		require.NoError(t, path.Switch())
		synctest.Wait()
		time.Sleep(rtt)
		synctest.Wait()

		// measure the throughput within the first second after migration
		after := measure(time.Second)

		t.Logf("throughput before=%d bytes/s, after=%d bytes/s (%.0f%%)",
			before, after, 100*float64(after)/float64(before))
		require.GreaterOrEqual(t, float64(after), 0.8*float64(before),
			"throughput after migration must recover to at least 80%% within one second")
	})
}
