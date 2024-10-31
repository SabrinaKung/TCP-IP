package tcp_layer

import (
	"net/netip"
	"sync"
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
	SeqNum     uint32
	AckNum     uint32

	// Channel for accepting new connections (for listener sockets)
	AcceptChan chan *Socket

	// Buffer management (can be expanded in future milestones)
	RecvBuffer []byte
	SendBuffer []byte
}
