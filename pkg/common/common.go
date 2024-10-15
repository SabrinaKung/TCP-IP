package common

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"net/netip"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
)

const (
	MessageSize      = 1024
	Infinite         = 16
	ProtocolTypeTest = 0
	ProtocolTypeRip  = 200
)

type RipEntry struct {
	Cost    uint32
	Address uint32
	Mask    uint32
}

type RipMessage struct {
	Command    uint16
	NumEntries uint16
	Entries    []RipEntry
}

func (d *RipMessage) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write Command and NumEntries
	if err := binary.Write(buf, binary.LittleEndian, d.Command); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, d.NumEntries); err != nil {
		return nil, err
	}

	// Write all entries
	for _, entry := range d.Entries {
		if err := binary.Write(buf, binary.LittleEndian, entry); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// Unmarshal binary RipMessage into the struct
func (d *RipMessage) UnmarshalBinary(RipMessage []byte) error {
	buf := bytes.NewReader(RipMessage)

	// Read Command and NumEntries
	if err := binary.Read(buf, binary.LittleEndian, &d.Command); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &d.NumEntries); err != nil {
		return err
	}

	// Read all entries
	d.Entries = make([]RipEntry, d.NumEntries)
	for i := 0; i < int(d.NumEntries); i++ {
		if err := binary.Read(buf, binary.LittleEndian, &d.Entries[i]); err != nil {
			return err
		}
	}

	return nil
}

func (d *RipMessage) PrefixToMask(bits int) uint32 {
	return ^uint32(0) << (32 - bits)
}

func (d *RipMessage) IpToUint32(ip netip.Addr) uint32 {
	ipBytes := ip.As4()
	return binary.BigEndian.Uint32(ipBytes[:])
}

func (d *RipMessage) Uint32ToPrefix(address uint32, mask uint32) netip.Prefix {
	var ipBytes [4]byte
	binary.BigEndian.PutUint32(ipBytes[:], address)
	ip := netip.AddrFrom4(ipBytes)
	bits := bits.OnesCount32(mask)
	return netip.PrefixFrom(ip, bits)
}

type IpPacket struct {
	Header  *ipv4header.IPv4Header
	Message []byte
}

type NetworkLayerAPI interface {
	ReceiveIpPacket(packet *IpPacket, thisHopIp netip.Addr) error
	UpdateFwdTable(ripMessage *RipMessage, src netip.Addr) error
	AdvertiseNeighbors(isResponse bool) error
	SendIP(dst netip.Addr, protocolNum uint8, data []byte) error
}

type LinkLayerAPI interface {
	SendIpPacket(ifName string, nextHopIp netip.Addr, packet IpPacket) error
	Initialize(configFile string) error
}

type HandlerFunc = func(*IpPacket, NetworkLayerAPI) error
