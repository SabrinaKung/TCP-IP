package common

import (
	"net/netip"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
)

const(
	MessageSize = 1024
)

type IpPacket struct{
	Header		*ipv4header.IPv4Header
	Message		[]byte 
}

type NetworkLayerAPI interface {
    ReceiveIpPacket(packet *IpPacket, thisHopIp netip.Addr) error
}


type LinkLayerAPI interface {
    SendIpPacket(ifName string, nextHopIp netip.Addr, packet IpPacket) error
	Initialize (configFile string) error
}

type HandlerFunc = func(*IpPacket) error