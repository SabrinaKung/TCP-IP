package main

import (
	"fmt"


	"team21/ip/pkg/common"
	"team21/ip/pkg/link_layer"
	"team21/ip/pkg/network_layer"
	// "team21/ip/pkg/common"
	// ipv4header "github.com/brown-csci1680/iptcp-headers"
)

func main(){
	link := &link_layer.LinkLayer{}
	network := &network_layer.NetworkLayer{}

	link.SetNetworkLayerApi(network)
	link.Initialize("/home/cs1680-user/ip-team-21/doc-example/r2.lnx")
	network.SetLinkLayerApi(link)
	network.Initialize("/home/cs1680-user/ip-team-21/doc-example/r2.lnx", true)
	network.RegisterRecvHandler(0, myPacketHandler)
	// **********************linkLayer test******************** 
	// addr, _ := netip.ParseAddr("10.0.0.2")
	// dst, _ := netip.ParseAddr("10.0.0.5")
	// data := []byte("test messageaaaaaaaaaaaaaaaaaaaaaaaa")
	// hdr := &ipv4header.IPv4Header{
	// 	Version:  4,
	// 	Len:      20, // Header length is always 20 when no IP options
	// 	TOS:      0,
	// 	TotalLen: ipv4header.HeaderLen + len(data),
	// 	ID:       0,
	// 	Flags:    0,
	// 	FragOff:  0,
	// 	TTL:      32,
	// 	Protocol: 0,
	// 	Checksum: 0, // Should be 0 until checksum is computed
	// 	Dst:      dst,
	// 	Options:  []byte{},
	// }
	// packet := common.IpPacket{
	// 	Header:     hdr,
	// 	Message: 	data,
	// }
	// err := link.SendIpPacket("if0", addr, packet)
	// if err != nil{
	// 	fmt.Println(err)
	// }


	// **********************networkLayer test******************** 
	
	for{

	}
}

func myPacketHandler(packet *common.IpPacket, networkApi common.NetworkLayerAPI) error {
    fmt.Printf("Packet from %s to %s\n", packet.Header.Src, packet.Header.Dst)
	fmt.Println(string(packet.Message))
    return nil
}