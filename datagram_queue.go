package quic

import (
	"context"
	"sync"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

const (
	maxDatagramSendQueueLen = 32
	maxDatagramRcvQueueLen  = 128
)

type datagramQueue struct {
	sendMx    sync.Mutex
	sendQueue ringbuffer.RingBuffer[*wire.DatagramFrame]

	rcvMx    sync.Mutex
	rcvQueue [][]byte
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	closeErr error
	closed   chan struct{}

	hasData func()

	logger  utils.Logger
	qlogger qlogwriter.Recorder
}

func newDatagramQueue(hasData func(), logger utils.Logger, qlogger qlogwriter.Recorder) *datagramQueue {
	return &datagramQueue{
		hasData: hasData,
		rcvd:    make(chan struct{}, 1),
		closed:  make(chan struct{}),
		logger:  logger,
		qlogger: qlogger,
	}
}

// Add queues a new DATAGRAM frame for sending.
// Up to maxDatagramSendQueueLen DATAGRAM frames will be queued.
// If the queue is full, [ErrDatagramQueueFull] is returned immediately,
// without blocking the caller.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()

	// don't queue frames after the connection is closed
	select {
	case <-h.closed:
		return h.closeErr
	default:
	}

	if h.sendQueue.Len() >= maxDatagramSendQueueLen {
		return ErrDatagramQueueFull
	}
	h.sendQueue.PushBack(f)
	h.hasData()
	return nil
}

// SendQueueLen returns the number of DATAGRAM frames currently queued for sending.
// It can be used as an input for pacing the sending of datagrams:
// a growing queue length indicates congestion on the path.
func (h *datagramQueue) SendQueueLen() int {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	return h.sendQueue.Len()
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if h.sendQueue.Empty() {
		return nil
	}
	return h.sendQueue.PeekFront()
}

func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	_ = h.sendQueue.PopFront()
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	data := make([]byte, len(f.Data))
	copy(data, f.Data)
	var queued bool
	h.rcvMx.Lock()
	if len(h.rcvQueue) < maxDatagramRcvQueueLen {
		h.rcvQueue = append(h.rcvQueue, data)
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	}
	h.rcvMx.Unlock()

	if !queued {
		if h.logger.Debug() {
			h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
		}
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.DatagramDropped{
				Direction: qlog.DirectionReceiving,
				Raw:       qlog.RawInfo{Length: len(f.Data), PayloadLength: qlog.OmitLength},
				Trigger:   "buffer_full",
			})
		}
	}
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	for {
		h.rcvMx.Lock()
		if len(h.rcvQueue) > 0 {
			data := h.rcvQueue[0]
			h.rcvQueue = h.rcvQueue[1:]
			h.rcvMx.Unlock()
			return data, nil
		}
		h.rcvMx.Unlock()
		select {
		case <-h.rcvd:
			continue
		case <-h.closed:
			return nil, h.closeErr
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.sendMx.Lock()
	h.sendQueue.Clear()
	h.sendMx.Unlock()

	h.rcvMx.Lock()
	h.rcvQueue = nil
	h.rcvMx.Unlock()

	h.closeErr = e
	// wake up all Add and Receive calls waiting on the closed channel
	close(h.closed)
}
