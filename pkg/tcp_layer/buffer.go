package tcp_layer

import (
	"fmt"
	"sync"
	"time"
)

const (
	DefaultBufferSize = 1024
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

	writeLen := uint32(len(data))
	if writeLen > available {
		fmt.Printf("Discard %d bytes.\n", writeLen-available)
		writeLen = available
	}
	fmt.Printf("%d bytes have been written to buffer!\n", writeLen)

	start := sb.sndLbw % uint32(len(sb.buffer))
	end := (start + writeLen) % uint32(len(sb.buffer))

	if start < end {
		copy(sb.buffer[start:end], data[:writeLen])
	} else {
		n := copy(sb.buffer[start:], data[:writeLen])
		copy(sb.buffer[:end], data[n:writeLen])
	}

	sb.sndLbw += writeLen
	sb.condEmpty.Signal() // Signal that data is available

	return int(writeLen), nil
}

func (sb *SendBuffer) ReadSegment(segmentSize uint32) (*Segment, error) {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	for sb.sndNxt == sb.sndLbw {
		sb.condEmpty.Wait()
	}

	// Don't read data that's already been acknowledged
	if sb.sndNxt < sb.sndUna {
		sb.sndNxt = sb.sndUna
	}

	// Start reading from sndNxt (which is now properly updated by ACKs)
	availableData := sb.sndLbw - sb.sndNxt
	if availableData < segmentSize {
		segmentSize = availableData
	}

	start := sb.sndNxt % uint32(len(sb.buffer))
	end := (start + segmentSize) % uint32(len(sb.buffer))

	var data []byte
	if start < end {
		data = make([]byte, end-start)
		copy(data, sb.buffer[start:end])
	} else {
		data = make([]byte, uint32(len(sb.buffer))-start+end)
		copy(data[:uint32(len(sb.buffer))-start], sb.buffer[start:])
		copy(data[uint32(len(sb.buffer))-start:], sb.buffer[:end])
	}

	segment := &Segment{
		Data:      data,
		SeqNum:    sb.sndNxt,
		Timestamp: time.Now().UnixNano(),
		Acked:     false,
		Length:    len(data),
	}

	// Don't update sndNxt here - it will be updated after successful send
	return segment, nil
}

func (sb *SendBuffer) Acknowledge(ackNum uint32) {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	// fmt.Printf("Acknowledge: %d\n", ackNum)
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
	condEmpty   sync.Cond
}

func NewReceiveBuffer(rcvNxt uint32) *ReceiveBuffer {
	ret := &ReceiveBuffer{
		buffer:      make([]byte, 0),
		rcvNxt:      rcvNxt,
		rcvWnd:      DefaultBufferSize,
		oooSegments: make([]*Segment, 0),
	}
	ret.condEmpty = *sync.NewCond(&ret.mutex)
	return ret
}

// ProcessSegment handles an incoming segment
func (rb *ReceiveBuffer) ProcessSegment(segment *Segment) error {
	rb.mutex.Lock()
	defer rb.mutex.Unlock()

	// Always process the segment, even if window is zero
	// This ensures we can still advance sequence numbers and send ACKs
	availableWindow := int(rb.rcvWnd)

	// If this is the next expected segment
	if segment.SeqNum == rb.rcvNxt {
		fmt.Printf("Processing in-order segment, SeqNum: %d, Length: %d, Available Window: %d\n",
			segment.SeqNum, len(segment.Data), availableWindow)

		if availableWindow > 0 {
			// Calculate how much data we can accept
			acceptLength := len(segment.Data)
			if acceptLength > availableWindow {
				acceptLength = availableWindow
			}

			// Add accepted data to buffer
			rb.buffer = append(rb.buffer, segment.Data[:acceptLength]...)

			// Update window and sequence number based on accepted data
			rb.rcvWnd -= uint16(acceptLength)
			rb.rcvNxt += uint32(acceptLength)

			// Process any buffered segments that are now in order
			rb.processBufferedSegments()
		} else {
			// fmt.Printf("Zero window advertised, maintaining sequence numbers but not accepting data\n")
			// Don't store data but maintain sequence tracking
			// This is crucial for zero window probing to work correctly
		}

		rb.condEmpty.Signal()
		return nil
	}

	// Handle out-of-order segment
	if segment.SeqNum > rb.rcvNxt {
		fmt.Printf("Buffering out-of-order segment, Expected: %d, Got: %d\n",
			rb.rcvNxt, segment.SeqNum)

		// Only buffer if we have window space
		if availableWindow > 0 {
			rb.bufferSegment(segment)
		}
		return nil
	}

	return nil
}

func (rb *ReceiveBuffer) Read(n int) ([]byte, error) {
	rb.mutex.Lock()
	defer rb.mutex.Unlock()

	for len(rb.buffer) == 0 {
		rb.condEmpty.Wait()
	}
	readLen := n
	if len(rb.buffer) < n {
		readLen = len(rb.buffer)
	}
	data := rb.buffer[:readLen]
	rb.buffer = rb.buffer[readLen:]

	// Update receive window as we free up space
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
