package link_layer

import (
	"log"
	"net"
	"net/netip"
	"team21/ip/pkg/common"
	"team21/ip/pkg/lnxconfig"
	"github.com/google/netstack/tcpip/header"
	ipv4header "github.com/brown-csci1680/iptcp-headers"
)

type LinklayerConfig struct{
	Interfaces []lnxconfig.InterfaceConfig
	Neighbors  []lnxconfig.NeighborConfig

	RoutingMode lnxconfig.RoutingMode
}

type LinkLayer struct {
    networkLayer 		common.NetworkLayerAPI
	linklayerConfig 	LinklayerConfig
	connMap 			map[string]*net.UDPConn
}

func NewLinkLayer(networkLayer common.NetworkLayerAPI) *LinkLayer {
    return &LinkLayer{networkLayer: networkLayer}
}

func (l *LinkLayer) Initialize (configFile string) error{
	temp, err := lnxconfig.ParseConfig(configFile)
	if err != nil{
		return err
	}
	l.linklayerConfig.Interfaces = temp.Interfaces
	l.linklayerConfig.Neighbors = temp.Neighbors
	l.linklayerConfig.RoutingMode = temp.RoutingMode

	l.connMap = make(map[string]*net.UDPConn)
	// Initialize interface 
	for _, i := range l.linklayerConfig.Interfaces{
		udpAddr := &net.UDPAddr{
			IP:   i.UDPAddr.Addr().AsSlice(),
			Port: int(i.UDPAddr.Port()),
		}
		// Bind on the local UDP port:  this sets the source port
		// and creates a conn
		conn, err := net.ListenUDP("udp4", udpAddr)
		if err != nil {
			return err
		}
		l.connMap[i.Name] = conn
	}

	// start goroutine to listen on udp port
	for _, conn := range l.connMap{
		go func(){
			for{
				buffer := make([]byte, common.MessageSize)
				bytesRead, sourceAddr, err := conn.ReadFromUDP(buffer)
				if err != nil{
					log.Println(err)
				}
				log.Printf("Received %d byte from %s", bytesRead, sourceAddr.String())
				err = l.handleUdpPacket(buffer, conn)
				if err != nil{
					log.Println(err)
				}
			}
		}()
	}
	return nil
}

func (l *LinkLayer) SendIpPacket(ifName string, nextHopIp netip.Addr, packet common.IpPacket) error{
	
	// compute checksum
	headerBytes, err := packet.Header.Marshal()
	if err != nil {
		return err
	}
	packet.Header.Checksum = int(computeChecksum(headerBytes)) + 1

	headerBytes, err = packet.Header.Marshal()
	if err != nil {
		log.Fatalln("Error marshalling header:  ", err)
	}

	// Append header + message into one byte array
	bytesToSend := make([]byte, 0, len(headerBytes) + len(packet.Message))
	bytesToSend = append(bytesToSend, headerBytes...)
	bytesToSend = append(bytesToSend, packet.Message...)

	// now the data to be send is ready, next is to deal with conn and addr
	var udpAddr *net.UDPAddr
	for _, neighbor := range l.linklayerConfig.Neighbors{
		if neighbor.DestAddr == nextHopIp{
			udpAddr = &net.UDPAddr{
				IP:   neighbor.UDPAddr.Addr().AsSlice(),
				Port: int(neighbor.UDPAddr.Port()),
			}
			break
		}
	}

	conn := l.connMap[ifName]
	bytesWritten, err := conn.WriteToUDP(bytesToSend, udpAddr)
	if err != nil {
		return err 
	}
	log.Printf("Sent %d bytes\n", bytesWritten)
	return nil 
}



func (l *LinkLayer) handleUdpPacket(buffer []byte, conn *net.UDPConn) error{
	// Marshal the received byte array into a UDP header
	hdr, err := ipv4header.ParseHeader(buffer)
	if err != nil {
		log.Println("Error parsing header", err)
		return nil
	}
	headerSize := hdr.Len

	// Validate the checksum
	headerBytes := buffer[:headerSize]
	checksumFromHeader := uint16(hdr.Checksum)
	computedChecksum := ValidateChecksum(headerBytes, checksumFromHeader)

	if computedChecksum != checksumFromHeader {
		log.Println("invalid checksum")
		return nil
	} 

	message := buffer[headerSize:]
	ipPacket := &common.IpPacket{
		Header: 	hdr,
		Message:    message,
	}

	localAddr, _ := netip.ParseAddrPort(conn.LocalAddr().String())
	for _, i := range l.linklayerConfig.Interfaces{
		if i.UDPAddr == localAddr{
			err := l.networkLayer.ReceiveIpPacket(*ipPacket, i.AssignedIP)
			_ = err 
			break
		}
	}
	return nil
}

func computeChecksum(b []byte) uint16 {
	checksum := header.Checksum(b, 0)

	// Invert the checksum value.  Why is this necessary?
	// This function returns the inverse of the checksum
	// on an initial computation.  While this may seem weird,
	// it makes it easier to use this same function
	// to validate the checksum on the receiving side.
	// See ValidateChecksum in the receiver file for details.
	checksumInv := checksum ^ 0xffff

	return checksumInv
}

func ValidateChecksum(b []byte, fromHeader uint16) uint16 {
	checksum := header.Checksum(b, fromHeader)

	return checksum
}