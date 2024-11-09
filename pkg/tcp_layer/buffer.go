package tcp_layer

import (
	"fmt"
	"sync"
	"time"
)

const (
	DefaultBufferSize = 65535
)

// // Circular buffer
// type RingBuffer struct {
// 	data     []byte
// 	start    int // Start of valid data
// 	end      int // End of valid data
// 	size     int // Current amount of data
// 	capacity int
// 	mutex    sync.Mutex
// }

// func NewRingBuffer(capacity int) *RingBuffer {
// 	return &RingBuffer{
// 		data:     make([]byte, capacity),
// 		capacity: capacity,
// 	}
// }

// func (rb *RingBuffer) Write(data []byte) (int, error) {
// 	rb.mutex.Lock()
// 	defer rb.mutex.Unlock()

// 	if len(data) > rb.available() {
// 		return 0, fmt.Errorf("buffer full")
// 	}

// 	written := 0
// 	for _, b := range data {
// 		rb.data[rb.end] = b
// 		rb.end = (rb.end + 1) % rb.capacity
// 		written++
// 		rb.size++
// 	}
// 	return written, nil
// }

// func (rb *RingBuffer) Read(n int) ([]byte, error) {
// 	rb.mutex.Lock()
// 	defer rb.mutex.Unlock()

// 	if rb.size == 0 {
// 		return nil, fmt.Errorf("buffer empty")
// 	}

// 	if n > rb.size {
// 		n = rb.size
// 	}

// 	result := make([]byte, n)
// 	for i := 0; i < n; i++ {
// 		result[i] = rb.data[rb.start]
// 		rb.start = (rb.start + 1) % rb.capacity
// 		rb.size--
// 	}
// 	return result, nil
// }

// func (rb *RingBuffer) available() int {
// 	return rb.capacity - rb.size
// }

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
	buffer          []byte
	sndUna          uint32 // oldest unacked sequence number
	sndNxt          uint32 // next sequence number to send
	sndWnd          uint16 // send window size
	sndLbw 			uint32 // last byte written by application
	initialSeqNum   uint32
	unackedSegments []*Segment
	mutex           sync.Mutex
	condEmpty       *sync.Cond 
	condSndWnd      *sync.Cond
}

func NewSendBuffer(isn uint32) *SendBuffer {
	sb := &SendBuffer{
		buffer:          make([]byte, DefaultBufferSize),
		sndUna:          isn,
		sndNxt:          isn,
		sndWnd:          DefaultBufferSize,
		sndLbw: 		 isn,
		initialSeqNum:   isn,
		unackedSegments: make([]*Segment, 0),
	}
	mutexEmpty := &sync.Mutex{}
	mutexSndWnd := &sync.Mutex{}
	sb.condEmpty = sync.NewCond(mutexEmpty)
	sb.condSndWnd = sync.NewCond(mutexSndWnd)
	return sb
}
// func NewSendBuffer(size uint32, initialSeq uint32) *SendBuffer {
// 	buf := &SendBuffer{
// 		buffer:         make([]byte, size),
// 		initialSeqNum:  initialSeq,
// 		unackedSegments: make([]*Segment, 0),
// 	}
// 	buf.condEmpty = sync.NewCond(&buf.mutex)
// 	buf.condSndWnd = sync.NewCond(&buf.mutex)
// 	return buf
// }

func (sb *SendBuffer) Write(data []byte) (int, error) {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	available := sb.AvailableSpace()
	if available == 0 {
		return 0, fmt.Errorf("send buffer is full")
	}

	writeLen := uint32(len(data))
	if writeLen > available {
		writeLen = available 
	}
	start := sb.sndLbw % uint32(len(sb.buffer))
	end := (start + writeLen) % uint32(len(sb.buffer))

	if start < end {
		copy(sb.buffer[start:end], data[:writeLen])
	} else {
		n := copy(sb.buffer[start:], data[:writeLen])
		copy(sb.buffer[:end], data[n:writeLen])
	}

	sb.sndLbw += writeLen

	// may exist problem
	sb.condEmpty.Signal() 

	return int(writeLen), nil
}


func (sb *SendBuffer) ReadSegment(segmentSize uint32) (*Segment, error) {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	for sb.sndNxt == sb.sndLbw {
		sb.condEmpty.Wait()
	}
	availableData := sb.sndLbw - sb.sndNxt
	if availableData < segmentSize {
		segmentSize = availableData
	}

	start := sb.sndNxt % uint32(len(sb.buffer))
	end := (start + segmentSize) % uint32(len(sb.buffer))

	var data []byte
	if start < end {
		data = sb.buffer[start:end]
	} else {
		data = append(sb.buffer[start:], sb.buffer[:end]...)
	}
	sb.sndNxt += segmentSize

	segment := &Segment{
		Data:      data,
		SeqNum:    sb.sndNxt - segmentSize,
		Timestamp: time.Now().UnixNano(), 
		Acked:     false,
		Length:    len(data),
	}

	return segment, nil
}


func (sb *SendBuffer) Acknowledge(ackNum uint32) {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	if ackNum > sb.sndUna && ackNum <= sb.sndLbw {
		sb.sndUna = ackNum 
	}
}

func (sb *SendBuffer) AvailableSpace() uint32 {
	used := sb.sndLbw - sb.sndUna
	return uint32(len(sb.buffer)) - used
}

func (sb *SendBuffer) AvailableData() uint32 {
	return sb.sndLbw - sb.sndNxt
}

func (sb *SendBuffer) UpdateWindowSize(newWnd uint16) {
	sb.condSndWnd.L.Lock()
	defer sb.condSndWnd.L.Unlock()

	sb.sndWnd = newWnd
	sb.condSndWnd.Signal()
}

// ReceiveBuffer manages the receiving side of TCP
type ReceiveBuffer struct {
	buffer      []byte
	rcvNxt      uint32 // next expected sequence number
	rcvWnd      uint16 // receive window size
	oooSegments []*Segment
	mutex       sync.Mutex
}

func NewReceiveBuffer(rcvNxt uint32) *ReceiveBuffer {
	return &ReceiveBuffer{
		buffer:      make([]byte, 0),
		rcvNxt:      rcvNxt,
		rcvWnd:      DefaultBufferSize,
		oooSegments: make([]*Segment, 0),
	}
}

// ProcessSegment handles an incoming segment
func (rb *ReceiveBuffer) ProcessSegment(segment *Segment) error {
	rb.mutex.Lock()
	defer rb.mutex.Unlock()

	if len(rb.buffer)+len(segment.Data) > int(rb.rcvWnd) {
		fmt.Printf("Segment too large for receive window, SeqNum: %d, Length: %d\n",
			segment.SeqNum, segment.Length)
		return fmt.Errorf("segment too large for receive window")
	}
	// Check if this is the next expected segment
	if segment.SeqNum == rb.rcvNxt {
		fmt.Printf("Processing in-order segment, SeqNum: %d, Length: %d\n",
			segment.SeqNum, segment.Length)

		// Add to buffer
		rb.buffer = append(rb.buffer, segment.Data...)
		// Update next expected sequence number
		rb.rcvNxt += uint32(segment.Length)
		rb.rcvWnd -= uint16(segment.Length)

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

	if len(rb.buffer) == 0 {
		return nil, nil
	}
	readLen := n
	if len(rb.buffer) < n {
		readLen = len(rb.buffer) 
	}
	data := rb.buffer[:readLen]
	rb.buffer = rb.buffer[readLen:]
	rb.rcvWnd += uint16(readLen)

	return data, nil
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
		rb.buffer = append(rb.buffer, segment.Data...)
		rb.rcvNxt += uint32(len(segment.Data))
		rb.rcvWnd -= uint16(segment.Length)
		rb.oooSegments = rb.oooSegments[1:]
	}
}
