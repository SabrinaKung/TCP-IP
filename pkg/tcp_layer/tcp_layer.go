package tcp_layer

import (
	"fmt"
	"net/netip"
	"sync"
	"team21/ip/pkg/common"
	"team21/ip/pkg/lnxconfig"
	"time"

	tcpUtils "team21/ip/pkg/tcp_layer/tcp_utils"

	"github.com/gammazero/deque"
	"github.com/google/netstack/tcpip/header"
)

type Tcp struct {
	socketQueue  *deque.Deque[*Socket]
	networkLayer common.NetworkLayerAPI
	localIp      netip.Addr
	nextSocketID int
	socketMutex  sync.Mutex
}

type Connection struct {
	socket *Socket
}

func (t *Tcp) getNextSocketID() int {
	t.socketMutex.Lock()
	defer t.socketMutex.Unlock()
	id := t.nextSocketID
	t.nextSocketID++
	return id
}

func (t *Tcp) Initialize(configFile string) error {
	temp, err := lnxconfig.ParseConfig(configFile)
	if err != nil {
		return err
	}
	t.localIp = temp.Interfaces[0].AssignedIP

	t.socketQueue = deque.New[*Socket]()

	t.nextSocketID = 0

	return nil
}

func (t *Tcp) SetNetworkLayerApi(networkLayer common.NetworkLayerAPI) {
	t.networkLayer = networkLayer
}

func (t *Tcp) Listen(port uint16) (*Socket, error) {
	socket := &Socket{
		ID:         t.getNextSocketID(),
		LocalAddr:  netip.IPv4Unspecified(), // Use 0.0.0.0
		LocalPort:  port,
		RemoteAddr: netip.IPv4Unspecified(), // Use 0.0.0.0
		RemotePort: 0,
		State:      LISTEN,
		AcceptChan: make(chan *Socket),
	}

	t.socketQueue.PushBack(socket)
	fmt.Printf("Created listen socket with ID %d\n", socket.ID)
	return socket, nil
}

func (t *Tcp) Connect(addr netip.Addr, port uint16) (*Connection, error) {
	localPort := tcpUtils.GenerateRandomPort()

	// fmt.Printf("Creating new connection socket: LocalPort:%d -> %s:%d\n",
	// 	localPort, addr, port)

	socket := &Socket{
		ID:         t.getNextSocketID(),
		RemoteAddr: addr,
		RemotePort: port,
		LocalPort:  localPort,
		LocalAddr:  t.localIp,
		State:      SYN_SENT,
		SeqNum:     tcpUtils.GenerateInitialSeqNum(),
		AckNum:     0,
	}

	// Add to queue BEFORE sending SYN
	t.socketQueue.PushBack(socket)

	// Send SYN
	err := t.SendTCPPacket(
		socket.LocalAddr,
		socket.LocalPort,
		socket.RemoteAddr,
		socket.RemotePort,
		[]byte{},
		header.TCPFlagSyn,
	)
	if err != nil {
		t.removeSocket(socket) // Clean up on send error
		return nil, fmt.Errorf("failed to send SYN: %v", err)
	}

	// Wait for connection to be established
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			socket.stateMutex.Lock()
			if socket.State == ESTABLISHED {
				socket.stateMutex.Unlock()
				return &Connection{socket: socket}, nil
			}
			socket.stateMutex.Unlock()
		case <-timeout:
			t.removeSocket(socket) // Clean up on timeout
			return nil, fmt.Errorf("connection timeout")
		}
	}
}

func (s *Socket) Accept() (*Socket, error) {
	newSocket := <-s.AcceptChan

	// Wait for the socket to be fully established
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			newSocket.stateMutex.Lock()
			if newSocket.State == ESTABLISHED {
				newSocket.stateMutex.Unlock()
				fmt.Printf("Accept: returning new established socket %d\n", newSocket.ID)
				return newSocket, nil
			}
			newSocket.stateMutex.Unlock()
		case <-timeout:
			return nil, fmt.Errorf("accept timeout waiting for connection to establish")
		}
	}
}

// func (t *Tcp) closeSocket(socket *Socket) {
// 	socket.stateMutex.Lock()
// 	socket.State = CLOSED
// 	socket.stateMutex.Unlock()
// 	t.removeSocket(socket)
// }

func (t *Tcp) HandleTCPPacket(packet *common.IpPacket, networkApi common.NetworkLayerAPI) error {
	tcpHeader := header.TCP(packet.Message[:header.TCPMinimumSize])
	// fmt.Printf("Received TCP packet with flags: %d from %s:%d\n",
	// 	tcpHeader.Flags(),
	// 	packet.Header.Src,
	// 	tcpHeader.SourcePort())

	socket := t.findSocket(tcpHeader)
	if socket == nil {
		return fmt.Errorf("no socket found for packet")
	}

	socket.stateMutex.Lock()
	defer socket.stateMutex.Unlock()

	// fmt.Printf("socket.State: %s\n", socket.State)

	switch socket.State {
	case LISTEN:
		if tcpHeader.Flags() == header.TCPFlagSyn {
			newSocket := &Socket{
				ID:         t.getNextSocketID(),
				LocalAddr:  t.localIp,
				LocalPort:  socket.LocalPort,
				RemoteAddr: packet.Header.Src,
				RemotePort: uint16(tcpHeader.SourcePort()),
				State:      SYN_RECEIVED,
				SeqNum:     tcpUtils.GenerateInitialSeqNum(),
				AckNum:     uint32(tcpHeader.SequenceNumber()) + 1,
			}

			// Add socket to queue before sending SYN-ACK
			t.socketQueue.PushBack(newSocket)

			// Send SYN-ACK after socket is in queue
			err := t.SendTCPPacket(
				newSocket.LocalAddr,
				newSocket.LocalPort,
				newSocket.RemoteAddr,
				newSocket.RemotePort,
				[]byte{},
				header.TCPFlagSyn|header.TCPFlagAck,
			)
			if err != nil {
				// If SYN-ACK fails, remove the socket from queue
				t.removeSocket(newSocket)
				return fmt.Errorf("failed to send SYN-ACK: %v", err)
			}
		}

	case SYN_SENT:
		if tcpHeader.Flags() == (header.TCPFlagSyn | header.TCPFlagAck) {
			// Received SYN-ACK (client side)
			socket.AckNum = uint32(tcpHeader.SequenceNumber()) + 1

			// Send ACK
			err := t.SendTCPPacket(
				socket.LocalAddr,
				socket.LocalPort,
				socket.RemoteAddr,
				socket.RemotePort,
				[]byte{},
				header.TCPFlagAck,
			)
			if err != nil {
				return fmt.Errorf("failed to send ACK: %v", err)
			}

			socket.State = ESTABLISHED
		}

	case SYN_RECEIVED:
		if tcpHeader.Flags() == header.TCPFlagAck {
			// Final ACK received (server side)
			socket.State = ESTABLISHED

			// Print the connection notification here, after receiving ACK
			fmt.Printf("New connection on socket %d => created new socket %d\n",
				0, // Assuming the listen socket always has ID 0
				socket.ID)

			if socket.AcceptChan != nil {
				socket.AcceptChan <- socket
			}
		}
	}

	return nil
}

func (t *Tcp) SendTCPPacket(sourceIp netip.Addr, sourcePort uint16,
	destIp netip.Addr, destPort uint16,
	payload []byte, tcpFlag uint8) error {

	// fmt.Printf("SendTCPPacket: sourceIp: %s, sourcePort: %d, destIp: %s, destPort: %d\n",
	// 	sourceIp, sourcePort, destIp, destPort)

	// Debug print all sockets in queue
	// fmt.Printf("Current sockets in queue:\n")
	// for i := 0; i < t.socketQueue.Len(); i++ {
	// 	s := t.socketQueue.At(i)
	// 	fmt.Printf("Socket %d: LocalAddr:%s, LocalPort:%d, RemoteAddr:%s, RemotePort:%d, State:%s\n",
	// 		s.ID, s.LocalAddr, s.LocalPort, s.RemoteAddr, s.RemotePort, s.State)
	// }

	// Find the socket for this connection
	var socket *Socket
	for i := 0; i < t.socketQueue.Len(); i++ {
		s := t.socketQueue.At(i)
		if s.LocalAddr == sourceIp && s.LocalPort == sourcePort &&
			s.RemoteAddr == destIp && s.RemotePort == destPort {
			socket = s
			// fmt.Printf("Found matching socket: ID %d\n", s.ID)
			break
		}
	}

	if socket == nil {
		return fmt.Errorf("no socket found for connection %s:%d -> %s:%d",
			sourceIp, sourcePort, destIp, destPort)
	}

	tcpHdr := header.TCPFields{
		SrcPort:       sourcePort,
		DstPort:       destPort,
		SeqNum:        socket.SeqNum,
		AckNum:        socket.AckNum,
		DataOffset:    20, // Standard TCP header size
		Flags:         tcpFlag,
		WindowSize:    65535,
		Checksum:      0,
		UrgentPointer: 0,
	}

	// Compute checksum
	checksum := tcpUtils.ComputeTCPChecksum(&tcpHdr, sourceIp, destIp, payload)
	tcpHdr.Checksum = checksum

	// Serialize the TCP header
	tcpHeaderBytes := make(header.TCP, tcpUtils.TcpHeaderLen)
	tcpHeaderBytes.Encode(&tcpHdr)

	// Combine header and payload
	ipPacketPayload := make([]byte, 0, len(tcpHeaderBytes)+len(payload))
	ipPacketPayload = append(ipPacketPayload, tcpHeaderBytes...)
	ipPacketPayload = append(ipPacketPayload, payload...)

	// Send via network layer
	err := t.networkLayer.SendIP(destIp, uint8(common.ProtocolTypeTcp), ipPacketPayload)
	if err != nil {
		return fmt.Errorf("failed to send TCP packet: %v", err)
	}

	// Update sequence number after sending
	if len(payload) > 0 {
		socket.SeqNum += uint32(len(payload))
	}
	if tcpFlag&header.TCPFlagSyn != 0 {
		socket.SeqNum++ // SYN counts as one byte
	}
	if tcpFlag&header.TCPFlagFin != 0 {
		socket.SeqNum++ // FIN counts as one byte
	}
	// print("finish SendTCPPacket\n")
	return nil
}

func (t *Tcp) findSocket(tcpHeader header.TCP) *Socket {
	srcPort := uint16(tcpHeader.SourcePort())
	dstPort := uint16(tcpHeader.DestinationPort())

	// fmt.Printf("Looking for socket with SrcPort:%d, DstPort:%d\n", srcPort, dstPort)

	// fmt.Printf("Current sockets in queue:\n")
	// for i := 0; i < t.socketQueue.Len(); i++ {
	// 	s := t.socketQueue.At(i)
	// 	fmt.Printf("Socket %d: LocalPort:%d, RemotePort:%d, State:%s\n",
	// 		s.ID, s.LocalPort, s.RemotePort, s.State)
	// }

	// First look for established or pending connections
	for i := 0; i < t.socketQueue.Len(); i++ {
		s := t.socketQueue.At(i)
		// For SYN_RECEIVED or ESTABLISHED sockets, match both ports exactly
		if s.State == SYN_RECEIVED || s.State == ESTABLISHED {
			if s.LocalPort == dstPort && s.RemotePort == srcPort {
				// fmt.Printf("Found matching socket in %s state: ID %d\n", s.State, s.ID)
				return s
			}
		}
		// For SYN_SENT sockets (client side)
		if s.State == SYN_SENT {
			if s.LocalPort == dstPort && s.RemotePort == srcPort {
				// fmt.Printf("Found matching socket in SYN_SENT state: ID %d\n", s.ID)
				return s
			}
		}
	}

	// Only look for LISTEN sockets if we don't find any matching connection
	// AND if this is a SYN packet
	if tcpHeader.Flags() == header.TCPFlagSyn {
		for i := 0; i < t.socketQueue.Len(); i++ {
			s := t.socketQueue.At(i)
			if s.State == LISTEN && s.LocalPort == dstPort {
				// fmt.Printf("Found matching LISTEN socket: ID %d\n", s.ID)
				return s
			}
		}
	}

	// fmt.Printf("No matching socket found!\n")
	return nil
}

func (t *Tcp) removeSocket(socket *Socket) {
	for i := 0; i < t.socketQueue.Len(); i++ {
		if t.socketQueue.At(i) == socket {
			t.socketQueue.Remove(i)
			break
		}
	}
}

func (t *Tcp) GetSockets() []*Socket {
	sockets := make([]*Socket, t.socketQueue.Len())
	for i := 0; i < t.socketQueue.Len(); i++ {
		sockets[i] = t.socketQueue.At(i)
	}
	return sockets
}
