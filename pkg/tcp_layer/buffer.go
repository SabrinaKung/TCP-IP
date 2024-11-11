package tcp_layer

import (
	"fmt"
	"sync"
	"time"
)

const (
	DefaultBufferSize = 10
)

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
	sndLbw          uint32 // last byte written by application
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
		sndLbw:          isn,
		initialSeqNum:   isn,
		unackedSegments: make([]*Segment, 0),
	}
	mutexEmpty := &sync.Mutex{}
	mutexSndWnd := &sync.Mutex{}
	sb.condEmpty = sync.NewCond(mutexEmpty)
	sb.condSndWnd = sync.NewCond(mutexSndWnd)
	return sb
}

func (sb *SendBuffer) Write(data []byte) (int, error) {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	available := sb.AvailableSpace()
	if available == 0 {
		return 0, fmt.Errorf("send buffer is full")
	}

	// Write data from application to send buffer
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
	// fmt.Println("sb.sndUna: ", sb.sndUna)
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

	availableWindow := int(rb.rcvWnd)
	if availableWindow <= 0 {
		fmt.Printf("Receive window is full, cannot accept any more data\n")
		return fmt.Errorf("receive window full")
	}

	// If segment data is larger than available window, only accept up to available window
	// Might not need this section
	dataToAccept := segment.Data
	if len(dataToAccept) > availableWindow {
		fmt.Printf("Segment too large, accepting partial data up to receive window limit, SeqNum: %d, Length: %d\n",
			segment.SeqNum, availableWindow)
		dataToAccept = dataToAccept[:availableWindow]
	}

	// Check if this is the next expected segment
	if segment.SeqNum == rb.rcvNxt {
		fmt.Printf("Processing in-order segment, SeqNum: %d, Length: %d\n",
			segment.SeqNum, len(dataToAccept))

		// Add accepted data to buffer
		rb.buffer = append(rb.buffer, dataToAccept...)
		// Update next expected sequence number
		rb.rcvNxt += uint32(len(dataToAccept))
		rb.rcvWnd -= uint16(len(dataToAccept))

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
		fmt.Printf("processBufferedSegments in oooSegments\n")
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
