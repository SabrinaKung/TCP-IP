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
	Socket *Socket // Use pointer to Socket
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
				return &Connection{Socket: socket}, nil
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
	tcpHdr := tcpUtils.ParseTCPHeader(packet.Message[:header.TCPMinimumSize])

	// fmt.Printf("Received TCP packet with flags: %d from %s:%d\n",
	// 	tcpHdr.Flags,
	// 	packet.Header.Src,
	// 	tcpHdr.SrcPort)

	tcpChecksumFromHeader := tcpHdr.Checksum // Save original
	tcpHdr.Checksum = 0
	tcpPayload := packet.Message[header.TCPMinimumSize:]
	tcpComputedChecksum := tcpUtils.ComputeTCPChecksum(&tcpHdr, packet.Header.Src, packet.Header.Dst, tcpPayload)

	// var tcpChecksumState string
	if tcpComputedChecksum == tcpChecksumFromHeader {
		// tcpChecksumState = "OK"
	} else {
		// tcpChecksumState = "FAIL"
		return fmt.Errorf("invalid tcp checksum")
	}
	// fmt.Printf("Received TCP packet with IP Header:  %v\nTCP header:  %+v\nFlags:  %s\nTCP Checksum:  %s\nPayload (%d bytes):  %s\n",
	// packet.Header, tcpHdr, tcpUtils.TCPFlagsAsString(tcpHdr.Flags), tcpChecksumState, len(tcpPayload), string(tcpPayload))

	socket := t.findSocket(tcpHdr, packet)
	if socket == nil {
		return fmt.Errorf("no socket found for packet")
	}

	socket.stateMutex.Lock()
	defer socket.stateMutex.Unlock()

	// fmt.Printf("Processing packet for socket ID %d in state %v\n", socket.ID, socket.State)

	switch socket.State {
	case LISTEN:
		if tcpHdr.Flags == header.TCPFlagSyn {
			// Create new connection socket
			newSocket := &Socket{
				ID:         t.getNextSocketID(),
				LocalAddr:  t.localIp,
				LocalPort:  socket.LocalPort,
				RemoteAddr: packet.Header.Src,
				RemotePort: uint16(tcpHdr.SrcPort),
				State:      SYN_RECEIVED,
			}

			// Initialize send buffer with a new ISN
			isn := tcpUtils.GenerateInitialSeqNum()
			newSocket.sendBuffer = NewSendBuffer(isn)

			// Initialize receive buffer with next expected sequence number
			remoteSeq := uint32(tcpHdr.SeqNum)
			newSocket.recvBuffer = NewReceiveBuffer(remoteSeq + 1)

			// Create connection ID and add to active sockets
			connID := ConnectionID{
				LocalAddr:  newSocket.LocalAddr,
				LocalPort:  newSocket.LocalPort,
				RemoteAddr: newSocket.RemoteAddr,
				RemotePort: newSocket.RemotePort,
			}
			t.activeSockets[connID] = newSocket
			socket.AcceptChan <- newSocket
			// Send SYN-ACK
			err := t.SendTCPPacket(
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
		if tcpHdr.Flags == (header.TCPFlagSyn | header.TCPFlagAck) {
			// Get remote's seq from the SYN-ACK packet
			remoteSeq := uint32(tcpHdr.SeqNum)

			// Update receive buffer's next expected sequence number
			socket.recvBuffer.rcvNxt = remoteSeq + 1

			// Update send sequence number - only increment once for SYN
			socket.sendBuffer.sndNxt += 1
			socket.sendBuffer.sndUna = socket.sendBuffer.sndNxt
			socket.sendBuffer.sndLbw = socket.sendBuffer.sndNxt

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
			t.StartSocketSending(socket)
		}

	case SYN_RECEIVED:
		if tcpHdr.Flags == header.TCPFlagAck {
			socket.sendBuffer.sndNxt += 1
			socket.sendBuffer.sndUna = socket.sendBuffer.sndNxt
			socket.sendBuffer.sndLbw = socket.sendBuffer.sndNxt
			socket.State = ESTABLISHED
			fmt.Printf("New connection on socket %d => created new socket %d\n",
				0, socket.ID)		
			t.StartSocketSending(socket)
		}

	case ESTABLISHED:
		// The TCP payload starts after the TCP header
		tcpPayload := packet.Message[header.TCPMinimumSize:]

		socket.sendBuffer.UpdateWindowSize(tcpHdr.WindowSize)
		socket.sendBuffer.ProcessAck(tcpHdr.AckNum)
		// fmt.Printf("socket.sendBuffer.sndUna: %d\n", socket.sendBuffer.sndUna)

		// Deal with tcp packet with payload
		if len(tcpPayload) > 0 {
			rcvSeqNum := uint32(tcpHdr.SeqNum)
			// fmt.Printf("Received data packet - Payload length: %d, SeqNum: %d\n",
			// len(tcpPayload), rcvSeqNum)

			segment := &Segment{
				Data:   tcpPayload,
				SeqNum: rcvSeqNum,
				Length: len(tcpPayload),
			}

			err := socket.recvBuffer.ProcessSegment(segment)
			if err != nil { // if buffer is full, drop the packet
				return fmt.Errorf("failed to process data: %v", err)
			}
			// fmt.Printf("rto : %d ms", socket.sendBuffer.rttStats.rto.Milliseconds())
			// Send ACK for received data
			err = t.SendTCPPacket(
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

	return nil
}

func (t *Tcp) SendTCPPacket(sourceIp netip.Addr, sourcePort uint16,
	destIp netip.Addr, destPort uint16,
	payload []byte, tcpFlag uint8, explicitSeqNum ...uint32) error {

	// fmt.Printf("payload: %s\n", payload)
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

	// Get sequence number - use explicit if provided, otherwise use sndNxt
	var seqNum uint32
	if len(explicitSeqNum) > 0 {
		seqNum = explicitSeqNum[0]
	} else {
		socket.sendBuffer.mutex.Lock()
		seqNum = socket.sendBuffer.sndNxt
		socket.sendBuffer.mutex.Unlock()
	}

	// fmt.Printf("socket.sendBuffer.sndNxt: %d\n", socket.sendBuffer.sndNxt)
	tcpHdr := header.TCPFields{
		SrcPort:       sourcePort,
		DstPort:       destPort,
		SeqNum:        seqNum,
		AckNum:        socket.recvBuffer.rcvNxt,
		DataOffset:    20,
		Flags:         tcpFlag,
		WindowSize:    socket.recvBuffer.rcvWnd,
		Checksum:      0,
		UrgentPointer: 0,
	}
	

	// Compute checksum
	checksum := tcpUtils.ComputeTCPChecksum(&tcpHdr, sourceIp, destIp, payload)
	tcpHdr.Checksum = checksum

	// Serialize the TCP header
	tcpHdrBytes := make(header.TCP, tcpUtils.TcpHeaderLen)
	tcpHdrBytes.Encode(&tcpHdr)

	// Combine header and payload
	ipPacketPayload := make([]byte, 0, len(tcpHdrBytes)+len(payload))
	ipPacketPayload = append(ipPacketPayload, tcpHdrBytes...)
	ipPacketPayload = append(ipPacketPayload, payload...)

	// Record transmission time for the segment
	if len(payload) > 0 {
		socket.sendBuffer.mutex.Lock()
		for _, segment := range socket.sendBuffer.unackedSegments {
			if segment.SeqNum == seqNum {
				segment.LastSent = time.Now()
				break
			}
		}
		socket.sendBuffer.mutex.Unlock()
	}

	// Send via network layer
	err := t.networkLayer.SendIP(destIp, uint8(common.ProtocolTypeTcp), ipPacketPayload)
	if err != nil {
		return fmt.Errorf("failed to send TCP packet: %v", err)
	}

	// print("finish SendTCPPacket\n")
	return nil
}

func (t *Tcp) findSocket(tcpHeader header.TCPFields, packet *common.IpPacket) *Socket {
	srcPort := uint16(tcpHeader.SrcPort)
	dstPort := uint16(tcpHeader.DstPort)

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
	if tcpHeader.Flags == header.TCPFlagSyn {
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

func (t *Tcp) StartSocketSending(s *Socket) {
	// TODO: add quit gracefully 
	go t.handleSending(s)        // Handle normal sending
	go t.handleZeroWndProbing(s) // Handle zero window probing
	go t.handleRetransmission(s) // Handle retransmission
}

func (t *Tcp) handleZeroWndProbing(s *Socket) {
	probeInterval := InitialProbeTimeout
	probeCount := 0

	for {
		s.sendBuffer.condSndWnd.L.Lock()
		for s.sendBuffer.sndWnd != 0 { // Wait until window becomes zero
			s.sendBuffer.condSndWnd.Wait()
		}
		s.sendBuffer.condSndWnd.L.Unlock()

		// Start probing cycle
		for s.State == ESTABLISHED {
			// Send a probe
			// fmt.Printf("Sending a probe s.sendBuffer.sndUna: %d  s.sendBuffer.sndNxt: %d, s.sendBuffer.sndLbw: %d\n", s.sendBuffer.sndUna, s.sendBuffer.sndNxt, s.sendBuffer.sndLbw)
			if s.sendBuffer.sndNxt < s.sendBuffer.sndLbw {
				fmt.Printf("Sending a probe with next un-acked byte\n")
				probeIndex := s.sendBuffer.sndNxt % uint32(len(s.sendBuffer.buffer))
				probe := []byte{s.sendBuffer.buffer[probeIndex]}

				err := t.SendTCPPacket(
					s.LocalAddr,
					s.LocalPort,
					s.RemoteAddr,
					s.RemotePort,
					probe,
					header.TCPFlagAck,
				)
				if err != nil {
					fmt.Printf("Failed to send zero window probe: %v\n", err)
					continue
				}
			}

			probeCount++
			currentInterval := probeInterval
			probeInterval = min(probeInterval*2, MaxProbeTimeout)

			// Wait for the probe interval
			time.Sleep(currentInterval)

			// Check if window has opened
			s.sendBuffer.condSndWnd.L.Lock()
			if s.sendBuffer.sndWnd > 0 {
				// Window has opened, reset probe parameters
				probeInterval = InitialProbeTimeout
				probeCount = 0
				s.sendBuffer.condSndWnd.L.Unlock()
				break
			}
			s.sendBuffer.condSndWnd.L.Unlock()
		}
	}
}

func (t *Tcp) handleSending(s *Socket) {
	for {
		// 1. Wait for data to be available
		s.sendBuffer.condEmpty.L.Lock()
		for s.sendBuffer.AvailableData() == 0 { // if there is no data to be sent, then wait
			s.sendBuffer.condEmpty.Wait() // wait on notification
		}

		// 2. Wait for send window to be non-zero
		s.sendBuffer.condSndWnd.L.Lock()
		for s.sendBuffer.sndWnd == 0 { // if send window is empty, then wait
			s.sendBuffer.condSndWnd.Wait()
		}

		windowSize := s.sendBuffer.sndWnd
		segment, err := s.sendBuffer.ReadSegment(uint32(min(windowSize, common.MaxTcpPayload)))

		if err != nil {
			fmt.Println("Error reading segment from send buffer:", err)
			s.sendBuffer.condEmpty.L.Unlock()
			s.sendBuffer.condSndWnd.L.Unlock()
			return
		}

		// Store the current sequence number in the segment
		segment.SeqNum = s.sendBuffer.sndNxt

		// Track unacknowledged segment
		s.sendBuffer.unackedSegments = append(s.sendBuffer.unackedSegments, segment)

		err = t.SendTCPPacket(
			s.LocalAddr,
			s.LocalPort,
			s.RemoteAddr,
			s.RemotePort,
			segment.Data,
			header.TCPFlagAck,
		)

		// Release locks
		s.sendBuffer.condEmpty.L.Unlock()
		s.sendBuffer.condSndWnd.L.Unlock()

		if err != nil {
			fmt.Println("Error sending packet:", err)
			return
		}
		s.sendBuffer.sndNxt += uint32(len(segment.Data))

		fmt.Printf("Sent %d bytes\n", len(segment.Data))

		// Wait for ACK before sending more data
		// This ensures we respect flow control
		time.Sleep(100 * time.Millisecond)
	}
}

func (t *Tcp) handleRetransmission(s *Socket) {
	for{
		s.sendBuffer.mutex.Lock()
		s.sendBuffer.rttStats.mu.Lock()
		if len(s.sendBuffer.unackedSegments) != 0 {
			segment := s.sendBuffer.unackedSegments[0]
			elapsed := time.Since(segment.LastSent)
			if elapsed > s.sendBuffer.rttStats.rto {
				tempRto := s.sendBuffer.rttStats.rto
				for segment.RetxCount < MaxTryTime{
					fmt.Printf("Retransmitting segment %d (elapsed: %v, RTO: %v)\n", 
						segment.SeqNum, elapsed, tempRto)
					s.sendBuffer.mutex.Unlock()
					err := t.SendTCPPacket(
						s.LocalAddr,
						s.LocalPort,
						s.RemoteAddr,
						s.RemotePort,
						segment.Data,
						header.TCPFlagAck,
						segment.SeqNum, // Pass original sequence number
					)
					s.sendBuffer.mutex.Lock()
					if err != nil {
						fmt.Printf("Failed to retransmit segment %d: %v\n", segment.SeqNum, err)
						continue
					}
					segment.RetxCount++
					segment.LastSent = time.Now()
					// tempRto *= 2
					// if tempRto > MaxRTO{
					// 	tempRto = MaxRTO
					// }
					s.sendBuffer.rttStats.mu.Unlock()
					s.sendBuffer.mutex.Unlock()
					time.Sleep(tempRto)
					s.sendBuffer.mutex.Lock()
					s.sendBuffer.rttStats.mu.Lock()
					if len(s.sendBuffer.unackedSegments) == 0 || (len(s.sendBuffer.unackedSegments) != 0 && s.sendBuffer.unackedSegments[0] != segment){
						break
					} 
				}
				// TODO disconnect when fail to retransmit
			}
		}
		s.sendBuffer.rttStats.mu.Unlock()
		s.sendBuffer.mutex.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
}
