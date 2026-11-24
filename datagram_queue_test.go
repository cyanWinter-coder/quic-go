package quic

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatagramQueuePeekAndPop(t *testing.T) {
	var queued []struct{}
	queue := newDatagramQueue(func() { queued = append(queued, struct{}{}) }, utils.DefaultLogger, nil)
	require.Nil(t, queue.Peek())
	require.Empty(t, queued)
	require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte("foo")}))
	require.Len(t, queued, 1)
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	// calling peek again returns the same datagram
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	queue.Pop()
	require.Nil(t, queue.Peek())
}

func TestDatagramQueueSendQueueLength(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, nil)

	// the queue accepts up to maxDatagramSendQueueLen datagrams, in FIFO order
	for i := range maxDatagramSendQueueLen {
		require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{byte(i)}}))
		require.Equal(t, i+1, queue.SendQueueLen())
	}

	// a full queue rejects new datagrams immediately, without blocking
	errChan := make(chan error, 1)
	go func() { errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, ErrDatagramQueueFull)
	case <-time.After(time.Second):
		t.Fatal("Add blocked on a full queue")
	}
	require.Equal(t, maxDatagramSendQueueLen, queue.SendQueueLen())

	// dequeueing happens in the same order as enqueueing
	for i := range maxDatagramSendQueueLen {
		f := queue.Peek()
		require.NotNil(t, f)
		require.Equal(t, []byte{byte(i)}, f.Data)
		queue.Pop()
	}
	require.Equal(t, 0, queue.SendQueueLen())
	require.Nil(t, queue.Peek())

	// after draining the queue, new datagrams are accepted again
	require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}))
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foobar")}, queue.Peek())
}

func TestDatagramQueueReceive(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, nil)

	// receive frames that were received earlier
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foo")})
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("bar")})
	data, err := queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), data)
	data, err = queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)
}

func TestDatagramQueueReceiveCanceledContext(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, nil)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foo")})

	// a canceled context takes precedence over queued datagrams
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := queue.Receive(ctx)
	require.ErrorIs(t, err, context.Canceled)

	// the datagram is still queued
	data, err := queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), data)
}

func TestDatagramQueueReceiveOverflow(t *testing.T) {
	qlogger := &events.Recorder{}
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, qlogger)
	for range maxDatagramRcvQueueLen {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("queued")})
	}
	require.Empty(t, qlogger.Events())

	f := &wire.DatagramFrame{Data: []byte("dropped"), DataLenPresent: true}
	queue.HandleDatagramFrame(f)
	require.Equal(t, []qlogwriter.Event{qlog.DatagramDropped{
		Direction: qlog.DirectionReceiving,
		Raw:       qlog.RawInfo{Length: len(f.Data), PayloadLength: qlog.OmitLength},
		Trigger:   "buffer_full",
	}}, qlogger.Events())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for range maxDatagramRcvQueueLen {
		data, err := queue.Receive(ctx)
		require.NoError(t, err)
		require.Equal(t, []byte("queued"), data)
	}
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("next")})
	data, err := queue.Receive(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("next"), data)
	require.Len(t, qlogger.Events(), 1)
}

func TestDatagramQueueReceiveBlocking(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger, nil)

		// block until a new frame is received
		type result struct {
			data []byte
			err  error
		}
		resultChan := make(chan result, 1)
		go func() {
			data, err := queue.Receive(context.Background())
			resultChan <- result{data, err}
		}()

		synctest.Wait()

		select {
		case <-resultChan:
			t.Fatal("expected to not receive result")
		default:
		}
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foobar")})
		synctest.Wait()
		select {
		case result := <-resultChan:
			require.NoError(t, result.err)
			require.Equal(t, []byte("foobar"), result.data)
		default:
			t.Fatal("should have received a datagram frame")
		}

		// unblock when the context is canceled
		ctx, cancel := context.WithCancel(context.Background())
		errChan := make(chan error, 1)
		go func() {
			_, err := queue.Receive(ctx)
			errChan <- err
		}()

		synctest.Wait()
		select {
		case <-errChan:
			t.Fatal("expected to not receive error")
		default:
		}

		cancel()
		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, context.Canceled)
		default:
			t.Fatal("should have received a context canceled error")
		}
	})
}

func TestDatagramQueueClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger, nil)

		for range maxDatagramSendQueueLen {
			require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
		}
		errChan := make(chan error, 1)
		go func() {
			_, err := queue.Receive(context.Background())
			errChan <- err
		}()

		synctest.Wait()

		queue.CloseWithError(assert.AnError)
		synctest.Wait()

		// the send queue is cleared
		require.Equal(t, 0, queue.SendQueueLen())
		require.Nil(t, queue.Peek())

		// all waiters are woken up
		select {
		case err := <-errChan:
			require.ErrorIs(t, err, assert.AnError)
		default:
			t.Fatal("should have received an error")
		}
	})
}

func TestDatagramQueueAddAfterClose(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, nil)
	queue.CloseWithError(assert.AnError)
	require.ErrorIs(t, queue.Add(&wire.DatagramFrame{Data: []byte("foo")}), assert.AnError)
	require.Nil(t, queue.Peek())
}

func TestDatagramQueueCloseRace(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, nil)

	const numAdds = 100
	errChan := make(chan error, numAdds)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range numAdds {
			errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("foo")})
		}
	}()
	queue.CloseWithError(assert.AnError)
	<-done

	// every Add either succeeded, was rejected because the queue was full,
	// or failed with the close error; it must never block
	var succeeded, full, closed int
	for range numAdds {
		err := <-errChan
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrDatagramQueueFull):
			full++
		default:
			require.ErrorIs(t, err, assert.AnError)
			closed++
		}
	}
	require.LessOrEqual(t, succeeded, maxDatagramSendQueueLen)
	require.Positive(t, full+closed)

	// the queue was cleared by the close
	require.Equal(t, 0, queue.SendQueueLen())
	require.Nil(t, queue.Peek())
	// adding after the close returns the close error
	require.ErrorIs(t, queue.Add(&wire.DatagramFrame{Data: []byte("foo")}), assert.AnError)
}
