package tcp_layer

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

type TCPState int

const (
	CLOSED TCPState = iota
	LISTEN
	SYN_SENT
	SYN_RECEIVED
	ESTABLISHED
)

func (s TCPState) String() string {
	switch s {
	case CLOSED:
		return "CLOSED"
	case LISTEN:
		return "LISTEN"
	case SYN_SENT:
		return "SYN_SENT"
	case SYN_RECEIVED:
		return "SYN_RECEIVED"
	case ESTABLISHED:
		return "ESTABLISHED"
	default:
		return "UNKNOWN"
	}
}

type Socket struct {
	ID int

	// Connection identifiers
	LocalAddr  netip.Addr
	LocalPort  uint16
	RemoteAddr netip.Addr
	RemotePort uint16

	// State management
	State      TCPState
	stateMutex sync.Mutex

	// Channel for accepting new connections (for listener sockets)
	AcceptChan chan *Socket

	// Buffer management
	sendBuffer *SendBuffer
	recvBuffer *ReceiveBuffer
}

func (s *Socket) VWrite(data []byte) (int, error) {
	if s.State != ESTABLISHED {
		return 0, fmt.Errorf("socket not connected")
	}

	// Write data to send buffer
	n, err := s.sendBuffer.Write(data)
	if err != nil {
		return 0, err
	}

	// Create segment
	segment := &Segment{
		Data:   data,
		SeqNum: s.sendBuffer.sndNxt,
		Length: len(data),
	}

	// Add to unacked segments before sending
	s.sendBuffer.unackedSegments = append(s.sendBuffer.unackedSegments, segment)

	return n, nil
}

// VRead reads data from the socket
func (s *Socket) VRead(n int) ([]byte, error) {
	if s.State != ESTABLISHED {
		return nil, fmt.Errorf("socket not connected")
	}

	data, err := s.recvBuffer.Read(n)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (s *Socket) startZeroWndProbing() {
	// zero window probing
	for {
		s.sendBuffer.condSndWnd.L.Lock()
		for s.sendBuffer.sndWnd != 0 { // if send window is not empty, then wait
			s.sendBuffer.condSndWnd.Wait()
		}

		// send 1 segment packet

		s.sendBuffer.condSndWnd.L.Unlock()
		time.Sleep(time.Second)

	}
}
