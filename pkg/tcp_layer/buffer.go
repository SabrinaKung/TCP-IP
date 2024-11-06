package tcp_layer

import (
	"fmt"
	"sync"
)

const (
	DefaultBufferSize = 65535
)

// Circular buffer
type RingBuffer struct {
	data     []byte
	start    int // Start of valid data
	end      int // End of valid data
	size     int // Current amount of data
	capacity int
	mutex    sync.Mutex
}

func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{
		data:     make([]byte, capacity),
		capacity: capacity,
	}
}

func (rb *RingBuffer) Write(data []byte) (int, error) {
	rb.mutex.Lock()
	defer rb.mutex.Unlock()

	if len(data) > rb.available() {
		return 0, fmt.Errorf("buffer full")
	}

	written := 0
	for _, b := range data {
		rb.data[rb.end] = b
		rb.end = (rb.end + 1) % rb.capacity
		written++
		rb.size++
	}
	return written, nil
}

func (rb *RingBuffer) Read(n int) ([]byte, error) {
	rb.mutex.Lock()
	defer rb.mutex.Unlock()

	if rb.size == 0 {
		return nil, fmt.Errorf("buffer empty")
	}

	if n > rb.size {
		n = rb.size
	}

	result := make([]byte, n)
	for i := 0; i < n; i++ {
		result[i] = rb.data[rb.start]
		rb.start = (rb.start + 1) % rb.capacity
		rb.size--
	}
	return result, nil
}

func (rb *RingBuffer) available() int {
	return rb.capacity - rb.size
}

// Segment represents a TCP segment with metadata
type Segment struct {
	Data      []byte
	SeqNum    uint32
	Timestamp int64
	Acked     bool
	Length    int
}

// SendBuffer manages the sending side of TCP
type SendBuffer struct {
	buffer          *RingBuffer
	sndUna          uint32 // oldest unacked sequence number
	sndNxt          uint32 // next sequence number to send
	sndWnd          uint16 // send window size
	lastByteWritten uint32 // last byte written by application
	initialSeqNum   uint32
	unackedSegments []*Segment
	mutex           sync.Mutex
}

func NewSendBuffer(isn uint32) *SendBuffer {
	return &SendBuffer{
		buffer:          NewRingBuffer(DefaultBufferSize),
		sndUna:          isn,
		sndNxt:          isn,
		sndWnd:          DefaultBufferSize,
		lastByteWritten: isn,
		initialSeqNum:   isn,
		unackedSegments: make([]*Segment, 0),
	}
}

// Write adds data to the send buffer
func (sb *SendBuffer) Write(data []byte) (int, error) {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	// Check if there's space in the window
	if uint32(len(data)) > uint32(sb.sndWnd) {
		return 0, fmt.Errorf("no space in send window")
	}

	n, err := sb.buffer.Write(data)
	if err != nil {
		return 0, err
	}

	sb.lastByteWritten += uint32(n)
	return n, nil
}

// ReceiveBuffer manages the receiving side of TCP
type ReceiveBuffer struct {
	buffer      *RingBuffer
	rcvNxt      uint32 // next expected sequence number
	rcvWnd      uint16 // receive window size
	oooSegments []*Segment
	mutex       sync.Mutex
}

func NewReceiveBuffer(rcvNxt uint32) *ReceiveBuffer {
	return &ReceiveBuffer{
		buffer:      NewRingBuffer(DefaultBufferSize),
		rcvNxt:      rcvNxt,
		rcvWnd:      DefaultBufferSize,
		oooSegments: make([]*Segment, 0),
	}
}

// ProcessSegment handles an incoming segment
func (rb *ReceiveBuffer) ProcessSegment(segment *Segment) error {
	rb.mutex.Lock()
	defer rb.mutex.Unlock()

	// Check if this is the next expected segment
	if segment.SeqNum == rb.rcvNxt {
		fmt.Printf("Processing in-order segment, SeqNum: %d, Length: %d\n",
			segment.SeqNum, segment.Length)

		// Add to buffer
		_, err := rb.buffer.Write(segment.Data)
		if err != nil {
			return fmt.Errorf("failed to write to receive buffer: %v", err)
		}

		// Update next expected sequence number
		rb.rcvNxt += uint32(segment.Length)

		// Process any buffered segments that are now in order
		rb.processBufferedSegments()
		return nil
	}

	// Handle out-of-order segment
	if segment.SeqNum > rb.rcvNxt {
		fmt.Printf("Buffering out-of-order segment, Expected: %d, Got: %d\n",
			rb.rcvNxt, segment.SeqNum)
		rb.bufferSegment(segment)
		return nil
	}

	return nil
}

func (rb *ReceiveBuffer) Read(n int) ([]byte, error) {
	rb.mutex.Lock()
	defer rb.mutex.Unlock()
	return rb.buffer.Read(n)
}

func (rb *ReceiveBuffer) bufferSegment(segment *Segment) {
	// Insert segment in order
	inserted := false
	for i, s := range rb.oooSegments {
		if segment.SeqNum < s.SeqNum {
			rb.oooSegments = append(rb.oooSegments[:i], append([]*Segment{segment}, rb.oooSegments[i:]...)...)
			inserted = true
			break
		}
	}
	if !inserted {
		rb.oooSegments = append(rb.oooSegments, segment)
	}
}

func (rb *ReceiveBuffer) processBufferedSegments() {
	for len(rb.oooSegments) > 0 {
		segment := rb.oooSegments[0]
		if segment.SeqNum != rb.rcvNxt {
			break
		}

		rb.buffer.Write(segment.Data)
		rb.rcvNxt += uint32(len(segment.Data))
		rb.oooSegments = rb.oooSegments[1:]
	}
}
