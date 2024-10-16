package network_layer

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"sync/atomic"
	"team21/ip/pkg/common"
	"team21/ip/pkg/lnxconfig"
	"time"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
)

type fwdTableEntry struct {
	RoutingType  RoutingType
	NextHopIP    netip.Addr
	NextHopIface string
	Prefix       netip.Prefix
	Cost         int
	lifeTime     *int32
}

func (n *NetworkLayer) insertEntry(entry *fwdTableEntry) {
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
				return entry
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
	linkLayer       		common.LinkLayerAPI
	ripNeighbors    		[]netip.Addr
	ForwardingTable 		[]*fwdTableEntry
	handlerMap      		map[uint8]common.HandlerFunc
	isRouter        		bool
	PeriodicUpdateRate 		int32
	routeTimeoutThreshold	int32
}

func (n *NetworkLayer) SetLinkLayerApi(linkLayer common.LinkLayerAPI) {
	n.linkLayer = linkLayer
}

func (n *NetworkLayer) Initialize(configFile string, isRouter bool) error {
	temp, err := lnxconfig.ParseConfig(configFile)
	if err != nil {
		return err
	}
	n.handlerMap = make(map[uint8]func(*common.IpPacket, common.NetworkLayerAPI) error)

	// Initialize static route
	for prefix, addr := range temp.StaticRoutes {
		var lifeTime int32
		atomic.StoreInt32(&lifeTime, 12)
		entry := fwdTableEntry{
			RoutingType: RoutingTypeStatic,
			NextHopIP:   addr,
			Cost:        0,
			Prefix:      prefix,
			lifeTime:    &lifeTime,
		}
		n.insertEntry(&entry)
	}
	// Initialize local route
	for _, neighbor := range temp.Neighbors {
		var lifeTime int32
		atomic.StoreInt32(&lifeTime, 12)
		entry := fwdTableEntry{
			RoutingType:  RoutingTypeLocal,
			NextHopIface: neighbor.InterfaceName,
			Cost:         0,
			lifeTime:     &lifeTime,
		}
		for _, iFace := range temp.Interfaces {
			if iFace.Name == neighbor.InterfaceName {
				entry.Prefix = iFace.AssignedPrefix
				break
			}
		}
		n.insertEntry(&entry)
	}

	// Initialize RipNeighbors
	if isRouter {
		n.PeriodicUpdateRate = common.DefaultPeriodicUpdateRate
		n.routeTimeoutThreshold = common.DefaultRouteTimeoutThreshold
		n.isRouter = true
		n.ripNeighbors = temp.RipNeighbors
		if temp.RipPeriodicUpdateRate != 0 {
			n.PeriodicUpdateRate = int32(temp.RipPeriodicUpdateRate.Seconds())
		}
		if temp.RipTimeoutThreshold != 0 {
			n.routeTimeoutThreshold = int32(temp.RipTimeoutThreshold.Seconds())
		}
		go n.countdownLifetime()
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
				handler(packet, n)
			}
		} else { // not my package, need to forward
			dst := packet.Header.Dst
			packet.Header.TTL -= 1
			fwdEntry := n.lookup(dst)
			nextIp := n.lookupNextIp(dst)
			if fwdEntry == nil {
				return nil
			}
			err := n.linkLayer.SendIpPacket(fwdEntry.NextHopIface, nextIp, *packet)
			if err != nil {
				return err
			}
			return nil
		}

	} else { //host does not need to forward package
		if packet.Header.Dst == thisHopIp {
			if handler, exists := n.handlerMap[uint8(packet.Header.Protocol)]; exists {
				handler(packet, n)
			}
		}
	}
	return nil
}

func (n *NetworkLayer) UpdateFwdTable(ripMsg *common.RipMessage, src netip.Addr) error {
	for _, entry := range ripMsg.Entries {
		prefix := ripMsg.Uint32ToPrefix(entry.Address, entry.Mask)
		receivedCost := int(entry.Cost)

		// Find the cost to the neighbor (src)
		costToNeighbor := n.getCostToNeighbor(src)
		if costToNeighbor == -1 {
			return fmt.Errorf("neighbor %s not found", src)
		}

		newCost := receivedCost + costToNeighbor + 1
		if newCost >= common.Infinite {
			newCost = common.Infinite
		}

		existingEntry := n.lookupExact(prefix)

		if existingEntry == nil {
			// Rule 1: If D not in table, add <D, c, N>
			newEntry := &fwdTableEntry{
				RoutingType: RoutingTypeRip,
				NextHopIP:   src,
				Prefix:      prefix,
				Cost:        newCost,
				lifeTime:    new(int32),
			}
			atomic.StoreInt32(newEntry.lifeTime, n.routeTimeoutThreshold)
			n.insertEntry(newEntry)
		} else {
			// Rule 2: If table has entry <D, M, cold>
			if newCost < existingEntry.Cost {
				// Lower cost, update
				existingEntry.NextHopIP = src
				existingEntry.Cost = newCost
				atomic.StoreInt32(existingEntry.lifeTime, n.routeTimeoutThreshold)
			} else if newCost > existingEntry.Cost && existingEntry.NextHopIP == src {
				// Cost increased for the current route
				existingEntry.Cost = newCost
				atomic.StoreInt32(existingEntry.lifeTime, n.routeTimeoutThreshold)
				// Trigger an update to neighbors
				n.AdvertiseNeighbors(true)
			} else if newCost == existingEntry.Cost && existingEntry.NextHopIP == src {
				// No change, just refresh timeout
				atomic.StoreInt32(existingEntry.lifeTime, n.routeTimeoutThreshold)
			}
			// If newCost > existingEntry.cost && existingEntry.nextHopIP != src, ignore
		}
	}
	return nil
}

func (n *NetworkLayer) lookupExact(prefix netip.Prefix) *fwdTableEntry {
	for _, entry := range n.ForwardingTable {
		if entry.Prefix == prefix {
			return entry
		}
	}
	return nil
}

func (n *NetworkLayer) getCostToNeighbor(neighbor netip.Addr) int {
	for _, entry := range n.ForwardingTable {
		if entry.RoutingType == RoutingTypeLocal && entry.Prefix.Contains(neighbor) {
			return entry.Cost // Usually 0 or 1 for direct neighbors
		}
	}
	return -1 // Neighbor not found
}

func (n *NetworkLayer) RegisterRecvHandler(protocolNum uint8, callbackFunc common.HandlerFunc) error {
	if _, exists := n.handlerMap[protocolNum]; exists {
		return fmt.Errorf("handler for protocol %d already exists", protocolNum)
	}
	n.handlerMap[protocolNum] = callbackFunc
	return nil
}

func (n *NetworkLayer) countdownLifetime() {
	for {
		for i := 0; i < len(n.ForwardingTable); i++ {
			entry := n.ForwardingTable[i]
			if entry.RoutingType == RoutingTypeRip {
				newLifeTime := atomic.AddInt32(entry.lifeTime, -1)
				if newLifeTime <= 0 {
					// Set the route’s cost to infinity (16)
					entry.Cost = common.Infinite
					// Send a triggered update
					err := n.AdvertiseNeighbors(true)
					if err != nil {
						log.Println(err)
					}
					// Remove the route from the routing table
					n.ForwardingTable = append(n.ForwardingTable[:i], n.ForwardingTable[i+1:]...)
				}
			}
		}
		time.Sleep(time.Second)
	}
}

func (n *NetworkLayer) AdvertiseNeighbors(isResponse bool) error {
	command := uint16(2) // Response by default
	if !isResponse {
		command = 1 // RIP request
	}

	for _, neighbor := range n.ripNeighbors {
		msg := &common.RipMessage{
			Command:    command,
			NumEntries: 0, // We'll set this after adding entries
		}

		for _, entry := range n.ForwardingTable {
			ripEntry := &common.RipEntry{}

			// Split horizon with poisoned reverse
			if entry.RoutingType == RoutingTypeRip && entry.NextHopIP == neighbor {
				ripEntry.Cost = uint32(common.Infinite)
			} else {
				ripEntry.Cost = uint32(entry.Cost)
			}
			ripEntry.Mask = msg.PrefixToMask(entry.Prefix.Bits())
			ripEntry.Address = msg.IpToUint32(entry.Prefix.Addr())
			msg.Entries = append(msg.Entries, *ripEntry)
		}

		// Set the correct number of entries
		msg.NumEntries = uint16(len(msg.Entries))

		msgByte, err := msg.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal RIP message: %v", err)
		}

		err = n.SendIP(neighbor, common.ProtocolTypeRip, msgByte)
		if err != nil {
			return fmt.Errorf("failed to send RIP message to %s: %v", neighbor, err)
		}
	}

	return nil
}
