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

type SocketManager struct {
	// Map sockets by local port for listeners
	ListeningSockets map[uint16]*Socket
	// Map active sockets by connection tuple (local addr:port, remote addr:port)
	ActiveSockets map[string]*Socket
	// For generating initial sequence numbers
	SeqNumGenerator uint32
}
