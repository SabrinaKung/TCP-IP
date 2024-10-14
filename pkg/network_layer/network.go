package network_layer

import (
	"fmt"
	"net/netip"
	"sort"
	"team21/ip/pkg/common"
	"team21/ip/pkg/lnxconfig"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
)

type fwdTableEntry struct {
	RoutingType  RoutingType
	NextHopIP    netip.Addr
	NextHopIface string
	Prefix       netip.Prefix
	Cost         int
}

func (n *NetworkLayer) insertEntry(entry fwdTableEntry) {
	n.ForwardingTable = append(n.ForwardingTable, entry)
	// Sort by prefix length in descending order
	sort.Slice(n.ForwardingTable, func(i, j int) bool {
		return n.ForwardingTable[i].Prefix.Bits() > n.ForwardingTable[j].Prefix.Bits()
	})
}

func (n *NetworkLayer) lookup(ip netip.Addr) *fwdTableEntry {
	for _, entry := range n.ForwardingTable {
		if entry.Prefix.Contains(ip) {
			if entry.RoutingType != RoutingTypeLocal {
				return n.lookup(entry.NextHopIP)
			} else {
				return &entry
			}
		}
	}
	return nil
}
func (n *NetworkLayer) lookupNextIp(ip netip.Addr) netip.Addr {
	for _, entry := range n.ForwardingTable {
		if entry.Prefix.Contains(ip) {
			if entry.RoutingType != RoutingTypeLocal {
				return entry.NextHopIP
			} else {
				return ip
			}
		}
	}
	return ip
}

type RoutingType int

const (
	RoutingTypeLocal  RoutingType = 0
	RoutingTypeRip    RoutingType = 1
	RoutingTypeStatic RoutingType = 2
)

type NetworkLayer struct {
	linkLayer       common.LinkLayerAPI
	ripNeighbors    []netip.Addr
	ForwardingTable []fwdTableEntry
	handlerMap      map[uint8]common.HandlerFunc
	isRouter        bool
}

func (n *NetworkLayer) SetLinkLayerApi(linkLayer common.LinkLayerAPI) {
	n.linkLayer = linkLayer
}

func (n *NetworkLayer) Initialize(configFile string, isRouter bool) error {
	temp, err := lnxconfig.ParseConfig(configFile)
	if err != nil {
		return err
	}
	n.handlerMap = make(map[uint8]func(*common.IpPacket) error)

	// Initialize static route
	for prefix, addr := range temp.StaticRoutes {
		entry := fwdTableEntry{
			RoutingType: RoutingTypeStatic,
			NextHopIP:   addr,
			Cost:        0,
			Prefix:      prefix,
		}
		n.insertEntry(entry)
	}
	// Initialize local route
	for _, neighbor := range temp.Neighbors {
		entry := fwdTableEntry{
			RoutingType:  RoutingTypeLocal,
			NextHopIface: neighbor.InterfaceName,
			Cost:         0,
		}
		for _, iFace := range temp.Interfaces {
			if iFace.Name == neighbor.InterfaceName {
				entry.Prefix = iFace.AssignedPrefix
				break
			}
		}
		n.insertEntry(entry)
	}

	// Initialize RipNeighbors
	if isRouter {
		n.isRouter = true
		n.ripNeighbors = temp.RipNeighbors
	}
	return nil
}

func (n *NetworkLayer) SendIP(dst netip.Addr, protocolNum uint8, data []byte) error {
	hdr := &ipv4header.IPv4Header{
		Version:  4,
		Len:      20, // Header length is always 20 when no IP options
		TOS:      0,
		TotalLen: ipv4header.HeaderLen + len(data),
		ID:       0,
		Flags:    0,
		FragOff:  0,
		TTL:      32,
		Protocol: int(protocolNum),
		Checksum: 0, // Should be 0 until checksum is computed
		Dst:      dst,
		Options:  []byte{},
	}
	packet := common.IpPacket{
		Header:  hdr,
		Message: data,
	}

	if n == nil {
		return fmt.Errorf("NetworkLayer is nil")
	}
	fwdEntry := n.lookup(dst)
	if fwdEntry == nil {
		return fmt.Errorf("forwarding entry for destination %v is nil", dst)
	}
	nextIp := n.lookupNextIp(dst)
	if !nextIp.IsValid() {
		return fmt.Errorf("next IP for destination %v is nil", dst)
	}
	err := n.linkLayer.SendIpPacket(fwdEntry.NextHopIface, nextIp, packet)
	if err != nil {
		return err
	}
	return nil
}

func (n *NetworkLayer) ReceiveIpPacket(packet *common.IpPacket, thisHopIp netip.Addr) error {
	if packet.Header.TTL == 0 {
		return nil // Drop packet with expired TTL
	}
	if n.isRouter {
		if packet.Header.Dst == thisHopIp { // package sent to router, usually is RIP package
			if handler, exists := n.handlerMap[uint8(packet.Header.Protocol)]; exists {
				handler(packet)
			}
		} else { // not my package, need to forward
			dst := packet.Header.Dst
			packet.Header.TTL -= 1
			fwdEntry := n.lookup(dst)
			nextIp := n.lookupNextIp(dst)
			err := n.linkLayer.SendIpPacket(fwdEntry.NextHopIface, nextIp, *packet)
			if err != nil {
				return err
			}
			return nil
		}

	} else { //host does not need to forward package
		if packet.Header.Dst == thisHopIp {
			if handler, exists := n.handlerMap[uint8(packet.Header.Protocol)]; exists {
				handler(packet)
			}
		}
	}
	return nil
}
func (n *NetworkLayer) RegisterRecvHandler(protocolNum uint8, callbackFunc common.HandlerFunc) error {
	if _, exists := n.handlerMap[protocolNum]; exists {
		return fmt.Errorf("handler for protocol %d already exists", protocolNum)
	}
	n.handlerMap[protocolNum] = callbackFunc
	return nil
}
