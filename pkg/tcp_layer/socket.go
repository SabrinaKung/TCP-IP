package tcp_layer

import (
	"fmt"
	"io"
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
	FIN_WAIT_1 // After sending FIN
	FIN_WAIT_2 // After receiving ACK of FIN
	TIME_WAIT  // After receiving FIN from other side
	CLOSE_WAIT // After receiving FIN from other side
	LAST_ACK   // After sending FIN (after CLOSE_WAIT)
)

const (
	InitialProbeTimeout = 1 * time.Second  // Initial probe timeout (RTO)
	MaxProbeTimeout     = 10 * time.Second // Maximum probe timeout
)

const (
	MSL = 15 * time.Second // Maximum Segment Lifetime
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
	case FIN_WAIT_1:
		return "FIN_WAIT_1"
	case FIN_WAIT_2:
		return "FIN_WAIT_2"
	case TIME_WAIT:
		return "TIME_WAIT"
	case CLOSE_WAIT:
		return "CLOSE_WAIT"
	case LAST_ACK:
		return "LAST_ACK"
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
	StateMutex sync.Mutex

	// Channel for accepting new connections (for listener sockets)
	AcceptChan chan *Socket

	// Buffer management
	sendBuffer *SendBuffer
	recvBuffer *ReceiveBuffer
}

func (s *Socket) VWrite(data []byte) (int, error) {
	// Check if socket has started closing process
	if s.State == FIN_WAIT_1 || s.State == FIN_WAIT_2 || s.State == TIME_WAIT {
		return 0, fmt.Errorf("cannot send after transport endpoint shutdown")
	}

	if s.State != ESTABLISHED && s.State != CLOSE_WAIT {
		return 0, fmt.Errorf("socket not connected")
	}

	// Write data to send buffer
	n, err := s.sendBuffer.Write(data)
	if err != nil {
		return 0, err
	}

	return n, nil
}

// VRead reads data from the socket
func (s *Socket) VRead(n int) ([]byte, error) {
	if s.State == FIN_WAIT_1 || s.State == FIN_WAIT_2 || s.State == TIME_WAIT {
		return nil, fmt.Errorf("operation not permitted")
	} else if s.State == CLOSE_WAIT {
		return nil, io.EOF
	}
	if s.State != ESTABLISHED {
		return nil, fmt.Errorf("socket not connected")
	}

	data, err := s.recvBuffer.Read(n, s)
	if err != nil {
		return nil, err
	}

	return data, nil
}
