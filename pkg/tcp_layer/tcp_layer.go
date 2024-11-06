package tcp_layer

import (
	"fmt"
	"net/netip"
	"sync"
	"team21/ip/pkg/common"
	"team21/ip/pkg/lnxconfig"
	"time"

	tcpUtils "team21/ip/pkg/tcp_layer/tcp_utils"

	"github.com/google/netstack/tcpip/header"
)

type Tcp struct {
	listenSockets map[uint16]*Socket       // key: local port
	activeSockets map[ConnectionID]*Socket // key: connection ID
	networkLayer  common.NetworkLayerAPI
	localIp       netip.Addr
	nextSocketID  int
	socketMutex   sync.Mutex
}

type Connection struct {
	socket *Socket // Use pointer to Socket
}

// ConnectionID uniquely identifies a TCP connection
type ConnectionID struct {
	LocalAddr  netip.Addr
	LocalPort  uint16
	RemoteAddr netip.Addr
	RemotePort uint16
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
		return fmt.Errorf("failed to parse config: %v", err)
	}

	// Initialize all maps
	t.listenSockets = make(map[uint16]*Socket)
	t.activeSockets = make(map[ConnectionID]*Socket)

	t.localIp = temp.Interfaces[0].AssignedIP
	t.nextSocketID = 0
	return nil
}

func (t *Tcp) SetNetworkLayerApi(networkLayer common.NetworkLayerAPI) {
	t.networkLayer = networkLayer
}

func (t *Tcp) Listen(port uint16) (*Socket, error) {
	// Check if port is already in use
	if _, exists := t.listenSockets[port]; exists {
		return nil, fmt.Errorf("port %d already in use", port)
	}

	isn := tcpUtils.GenerateInitialSeqNum()

	socket := &Socket{
		ID:         t.getNextSocketID(),
		LocalAddr:  netip.IPv4Unspecified(), // Use 0.0.0.0
		LocalPort:  port,
		RemoteAddr: netip.IPv4Unspecified(), // Use 0.0.0.0
		RemotePort: 0,
		State:      LISTEN,
		AcceptChan: make(chan *Socket),
		sendBuffer: NewSendBuffer(isn),
		recvBuffer: NewReceiveBuffer(0),
		sendPacket: t.SendTCPPacket,
	}

	t.listenSockets[port] = socket
	fmt.Printf("Created listen socket with ID %d\n", socket.ID)
	return socket, nil
}

func (t *Tcp) Connect(addr netip.Addr, port uint16) (*Connection, error) {
	localPort := tcpUtils.GenerateRandomPort()

	// fmt.Printf("Creating new connection socket: LocalPort:%d -> %s:%d\n",
	// 	localPort, addr, port)

	isn := tcpUtils.GenerateInitialSeqNum()

	socket := &Socket{
		ID:         t.getNextSocketID(),
		RemoteAddr: addr,
		RemotePort: port,
		LocalPort:  localPort,
		LocalAddr:  t.localIp,
		State:      SYN_SENT,
		sendBuffer: NewSendBuffer(isn),
		recvBuffer: NewReceiveBuffer(0),
		sendPacket: t.SendTCPPacket,
	}

	// Create connection ID
	connID := ConnectionID{
		LocalAddr:  socket.LocalAddr,
		LocalPort:  socket.LocalPort,
		RemoteAddr: socket.RemoteAddr,
		RemotePort: socket.RemotePort,
	}

	// Add to active sockets map
	t.socketMutex.Lock()
	t.activeSockets[connID] = socket
	t.socketMutex.Unlock()

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

	socket := t.findSocket(tcpHeader, packet)
	if socket == nil {
		return fmt.Errorf("no socket found for packet")
	}

	socket.stateMutex.Lock()
	defer socket.stateMutex.Unlock()

	// fmt.Printf("Processing packet for socket ID %d in state %v\n", socket.ID, socket.State)

	switch socket.State {
	case LISTEN:
		if tcpHeader.Flags() == header.TCPFlagSyn {
			// Create new connection socket
			newSocket := &Socket{
				ID:         t.getNextSocketID(),
				LocalAddr:  t.localIp,
				LocalPort:  socket.LocalPort,
				RemoteAddr: packet.Header.Src,
				RemotePort: uint16(tcpHeader.SourcePort()),
				State:      SYN_RECEIVED,
				sendPacket: t.SendTCPPacket,
			}

			// Initialize send buffer with a new ISN
			isn := tcpUtils.GenerateInitialSeqNum()
			newSocket.sendBuffer = NewSendBuffer(isn)

			// Initialize receive buffer with next expected sequence number
			remoteSeq := uint32(tcpHeader.SequenceNumber())
			newSocket.recvBuffer = NewReceiveBuffer(remoteSeq + 1)

			// Create connection ID and add to active sockets
			connID := ConnectionID{
				LocalAddr:  newSocket.LocalAddr,
				LocalPort:  newSocket.LocalPort,
				RemoteAddr: newSocket.RemoteAddr,
				RemotePort: newSocket.RemotePort,
			}
			t.activeSockets[connID] = newSocket

			// Send SYN-ACK
			err := newSocket.sendPacket(
				newSocket.LocalAddr,
				newSocket.LocalPort,
				newSocket.RemoteAddr,
				newSocket.RemotePort,
				[]byte{},
				header.TCPFlagSyn|header.TCPFlagAck,
			)
			if err != nil {
				t.removeSocket(newSocket)
				return fmt.Errorf("failed to send SYN-ACK: %v", err)
			}
		}

	case SYN_SENT:
		if tcpHeader.Flags() == (header.TCPFlagSyn | header.TCPFlagAck) {
			// Get remote's seq from the SYN-ACK packet
			remoteSeq := uint32(tcpHeader.SequenceNumber())

			// Update receive buffer's next expected sequence number
			socket.recvBuffer.rcvNxt = remoteSeq + 1

			// Update send sequence number - only increment once for SYN
			socket.sendBuffer.sndNxt = socket.sendBuffer.sndUna + 1
			socket.sendBuffer.sndUna = socket.sendBuffer.sndNxt

			err := socket.sendPacket(
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
			socket.State = ESTABLISHED
			fmt.Printf("New connection on socket %d => created new socket %d\n",
				0, socket.ID)

			if socket.AcceptChan != nil {
				socket.AcceptChan <- socket
			}
		}

	case ESTABLISHED:
		if len(packet.Message) > header.TCPMinimumSize {
			// We already have the TCP header from earlier parsing
			// The TCP payload starts after the TCP header
			tcpPayload := packet.Message[header.TCPMinimumSize:]

			if len(tcpPayload) > 0 {
				rcvSeqNum := uint32(tcpHeader.SequenceNumber())

				fmt.Printf("Received data packet - Payload length: %d, SeqNum: %d\n",
					len(tcpPayload), rcvSeqNum)

				segment := &Segment{
					Data:   tcpPayload,
					SeqNum: rcvSeqNum,
					Length: len(tcpPayload),
				}

				err := socket.recvBuffer.ProcessSegment(segment)
				if err != nil {
					return fmt.Errorf("failed to process data: %v", err)
				}

				// Send ACK for received data
				err = socket.sendPacket(
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
			}
		}
	}

	return nil
}

func (t *Tcp) SendTCPPacket(sourceIp netip.Addr, sourcePort uint16,
	destIp netip.Addr, destPort uint16,
	payload []byte, tcpFlag uint8) error {

	// Create connection ID to find the socket
	connID := ConnectionID{
		LocalAddr:  sourceIp,
		LocalPort:  sourcePort,
		RemoteAddr: destIp,
		RemotePort: destPort,
	}

	// Find the socket
	t.socketMutex.Lock()
	socket, exists := t.activeSockets[connID]
	t.socketMutex.Unlock()

	if !exists {
		return fmt.Errorf("no socket found for connection %s:%d -> %s:%d",
			sourceIp, sourcePort, destIp, destPort)
	}

	tcpHdr := header.TCPFields{
		SrcPort:       sourcePort,
		DstPort:       destPort,
		SeqNum:        socket.sendBuffer.sndNxt,
		AckNum:        socket.recvBuffer.rcvNxt,
		DataOffset:    20,
		Flags:         tcpFlag,
		WindowSize:    65535,
		Checksum:      0,
		UrgentPointer: 0,
	}

	// Only increment sequence number after constructing header
	if tcpFlag&header.TCPFlagSyn != 0 {
		socket.sendBuffer.sndNxt++ // SYN consumes one sequence number
	} else if len(payload) > 0 {
		socket.sendBuffer.sndNxt += uint32(len(payload))
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

	// print("finish SendTCPPacket\n")
	return nil
}

func (t *Tcp) findSocket(tcpHeader header.TCP, packet *common.IpPacket) *Socket {
	srcPort := uint16(tcpHeader.SourcePort())
	dstPort := uint16(tcpHeader.DestinationPort())

	// First check active connections
	connID := ConnectionID{
		LocalPort:  dstPort,
		LocalAddr:  packet.Header.Dst,
		RemotePort: srcPort,
		RemoteAddr: packet.Header.Src,
	}

	t.socketMutex.Lock()
	defer t.socketMutex.Unlock()

	// fmt.Printf("Looking for socket with LocalPort:%d, RemotePort:%d\n", dstPort, srcPort)
	// fmt.Printf("Active sockets:\n")
	// for id, sock := range t.activeSockets {
	// 	fmt.Printf("Socket ID %d: Local %s:%d, Remote %s:%d, State: %v\n",
	// 		sock.ID, id.LocalAddr, id.LocalPort, id.RemoteAddr, id.RemotePort, sock.State)
	// }

	if socket, exists := t.activeSockets[connID]; exists {
		// fmt.Printf("Found active socket: ID %d\n", socket.ID)
		return socket
	}

	// If not found and it's a SYN packet, check listening sockets
	if tcpHeader.Flags() == header.TCPFlagSyn {
		if socket, exists := t.listenSockets[dstPort]; exists {
			// fmt.Printf("Found listening socket: ID %d\n", socket.ID)
			return socket
		}
	}

	// fmt.Printf("No matching socket found!\n")
	return nil
}

func (t *Tcp) removeSocket(socket *Socket) {
	t.socketMutex.Lock()
	defer t.socketMutex.Unlock()

	if socket.State == LISTEN {
		delete(t.listenSockets, socket.LocalPort)
	} else {
		connID := ConnectionID{
			LocalAddr:  socket.LocalAddr,
			LocalPort:  socket.LocalPort,
			RemoteAddr: socket.RemoteAddr,
			RemotePort: socket.RemotePort,
		}
		delete(t.activeSockets, connID)
	}
}

func (t *Tcp) GetSockets() []*Socket {
	t.socketMutex.Lock()
	defer t.socketMutex.Unlock()

	// Calculate total number of sockets
	totalSockets := len(t.listenSockets) + len(t.activeSockets)
	sockets := make([]*Socket, 0, totalSockets)

	// Add listening sockets
	for _, socket := range t.listenSockets {
		sockets = append(sockets, socket)
	}

	// Add active sockets
	for _, socket := range t.activeSockets {
		sockets = append(sockets, socket)
	}

	return sockets
}

type SendPacketFunc func(sourceIp netip.Addr, sourcePort uint16,
	destIp netip.Addr, destPort uint16,
	payload []byte, tcpFlag uint8) error

func (sb *SendBuffer) HandleAck(ackNum uint32) {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	// Only update if this ACK advances the window
	if ackNum > sb.sndUna {
		sb.sndUna = ackNum
	}
}
