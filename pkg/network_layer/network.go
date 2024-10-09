package network_layer

import (
	"net/netip"
	"sort"
	"team21/ip/pkg/common"
	"team21/ip/pkg/lnxconfig"
	ipv4header "github.com/brown-csci1680/iptcp-headers"
)

type fwdTableEntry struct{
	routingType		routingType;
	nextHopIP    	netip.Addr  
	nextHopIface 	string       
	prefix			netip.Prefix;
	cost 			int;
}

func (n *NetworkLayer) insertEntry(entry fwdTableEntry) {
	n.forwardingTable = append(n.forwardingTable, entry)
	// Sort by prefix length in descending order
	sort.Slice(n.forwardingTable, func(i, j int) bool {
		return n.forwardingTable[i].prefix.Bits() > n.forwardingTable[j].prefix.Bits()
	})
}

func (n *NetworkLayer) lookup(ip netip.Addr) *fwdTableEntry {
	for _, entry := range n.forwardingTable {
		if entry.prefix.Contains(ip) {
			if entry.routingType != routingTypeLocal{
				return n.lookup(entry.nextHopIP)
			} else {
				return &entry
			}
		}
	}
	return nil 
}
func (n *NetworkLayer) lookupNextIp(ip netip.Addr) netip.Addr{
	for _, entry := range n.forwardingTable {
		if entry.prefix.Contains(ip) {
			if entry.routingType != routingTypeLocal{
				return entry.nextHopIP
			} else {
				return ip
			}
		}
	}
	return ip
}

type routingType int
const (
	routingTypeLocal  	 routingType = 0
	routingTypeRip 		 routingType = 1
	routingTypeStatic    routingType = 2
)


type NetworkLayer struct {
    linkLayer 			common.LinkLayerAPI
	RipNeighbors 		[]netip.Addr
	forwardingTable 	[] fwdTableEntry
}

func NewNetworkLayer(linkLayer common.LinkLayerAPI) *NetworkLayer {
    return &NetworkLayer{linkLayer: linkLayer}
}

func (n *NetworkLayer) Initialize (configFile string, isRouter bool) error{
	temp, err := lnxconfig.ParseConfig(configFile)
	if err != nil{
		return err
	}
	// Initialize static route 
	for prefix, addr := range(temp.StaticRoutes){
		entry := fwdTableEntry{
			routingType: 	routingTypeStatic,
			nextHopIP: 		addr,
			cost:			0,
			prefix: 		prefix,
		}
		n.insertEntry(entry)
	}
	// Initialize local route 
	for _, neighbor := range(temp.Neighbors){
		entry := fwdTableEntry{
			routingType: 	routingTypeLocal,
			nextHopIface: 	neighbor.InterfaceName,
			cost:			0,
		}
		for _, iFace := range(temp.Interfaces){
			if iFace.Name == neighbor.InterfaceName{
				entry.prefix = iFace.AssignedPrefix
			}
			break
		}
		n.insertEntry(entry)
	}

	// Initialize RipNeighbors
	if isRouter{
		n.RipNeighbors = temp.RipNeighbors
	}
	return nil 
}

func (n *NetworkLayer) SendIP(dst netip.Addr, protocolNum uint8, data []byte) error{
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
		Header:     hdr,
		Message: 	data,
	}

	fwdEntry := n.lookup(dst)
	nextIp   := n.lookupNextIp(dst)
	err := n.linkLayer.SendIpPacket(fwdEntry.nextHopIface, nextIp, packet)
	if err != nil{
		return err
	}
	return nil 
}

func (n *NetworkLayer) ReceiveIpPacket(packet common.IpPacket, thisHopIp netip.Addr) error{
	return nil 
}