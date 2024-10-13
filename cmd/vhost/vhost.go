package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"team21/ip/pkg/common"
	"team21/ip/pkg/link_layer"
	"team21/ip/pkg/network_layer"
)

func main() {
	configFile := flag.String("config", "", "Path to the config file")
	flag.Parse()

	if *configFile == "" {
		log.Fatal("Config file path is required")
	}

	link := &link_layer.LinkLayer{}
	network := &network_layer.NetworkLayer{}

	link.SetNetworkLayerApi(network)
	err := link.Initialize(*configFile)
	if err != nil {
		log.Fatalf("Failed to initialize link layer: %v", err)
	}

	network.SetLinkLayerApi(link)
	err = network.Initialize(*configFile, false)
	if err != nil {
		log.Fatalf("Failed to initialize network layer: %v", err)
	}

	network.RegisterRecvHandler(0, myPacketHandler)

	// Start the command-line interface
	runCLI(network, link)
}

func myPacketHandler(packet *common.IpPacket) error {
	fmt.Printf("Received test packet: Src: %s, Dst: %s, TTL: %d, Data: %s\n",
		packet.Header.Src,
		packet.Header.Dst,
		packet.Header.TTL,
		string(packet.Message))
	return nil
}

func runCLI(network *network_layer.NetworkLayer, link *link_layer.LinkLayer) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		command := scanner.Text()
		parts := strings.Fields(command)
		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "send":
			if len(parts) != 3 {
				fmt.Println("Usage: send <destination_ip> <message>")
				continue
			}
			destIP, err := netip.ParseAddr(parts[1])
			if err != nil {
				fmt.Printf("Invalid IP address: %v\n", err)
				continue
			}
			message := []byte(parts[2])
			err = network.SendIP(destIP, 0, message) // 0 is for test protocol
			if err != nil {
				fmt.Printf("Failed to send message: %v\n", err)
			} else {
				fmt.Println("Message sent successfully")
			}
		case "li":
			listInterfaces(link)
		case "ln":
			listNeighbors(link)
		case "up":
			if len(parts) != 2 {
				fmt.Println("Usage: up <ifname>")
				continue
			}
			enableInterface(link, parts[1])
		case "down":
			if len(parts) != 2 {
				fmt.Println("Usage: down <ifname>")
				continue
			}
			disableInterface(link, parts[1])
		case "exit", "q":
			return
		default:
			fmt.Println("Unknown command. Available commands: send, li, ln, exit, q")
		}
	}
}

func enableInterface(link *link_layer.LinkLayer, ifName string) {
	if _, exists := link.IfaceStatus[ifName]; !exists {
		fmt.Printf("Interface %s does not exist\n", ifName)
		return
	}
	link.IfaceStatus[ifName] = "up"
}

func disableInterface(link *link_layer.LinkLayer, ifName string) {
	if _, exists := link.IfaceStatus[ifName]; !exists {
		fmt.Printf("Interface %s does not exist\n", ifName)
		return
	}
	link.IfaceStatus[ifName] = "down"
}

func listInterfaces(link *link_layer.LinkLayer) {
	fmt.Println("Name  Addr/Prefix State")
	for _, iface := range link.LinklayerConfig.Interfaces {
		fmt.Printf(" %-4s %-12s %-15s\n", iface.Name, fmt.Sprintf("%s/%d", iface.AssignedIP, iface.AssignedPrefix.Bits()), link.IfaceStatus[iface.Name])
	}
}

func listNeighbors(link *link_layer.LinkLayer) {
	fmt.Println("Iface          VIP          UDPAddr")
	for _, iface := range link.LinklayerConfig.Interfaces {
		for _, neighbor := range link.LinklayerConfig.Neighbors {
			if neighbor.InterfaceName == iface.Name {
				fmt.Printf(" %-4s %11s %16s\n",
					neighbor.InterfaceName,
					neighbor.DestAddr,
					neighbor.UDPAddr)
			}
		}
	}
}
