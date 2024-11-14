package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"team21/ip/pkg/common"
	"team21/ip/pkg/link_layer"
	"team21/ip/pkg/network_layer"
	"team21/ip/pkg/tcp_layer"
	"time"
)

var tcpStack *tcp_layer.Tcp

func main() {
	configFile := flag.String("config", "", "Path to the config file")
	flag.Parse()

	if *configFile == "" {
		log.Fatal("Config file path is required")
	}

	link := &link_layer.LinkLayer{}
	network := &network_layer.NetworkLayer{}
	tcpStack = &tcp_layer.Tcp{}

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
	network.RegisterRecvHandler(common.ProtocolTypeTcp, tcpStack.HandleTCPPacket)

	err = tcpStack.Initialize(*configFile)
	if err != nil {
		log.Fatalf("Failed to initialize TCP layer: %v", err)
	}
	tcpStack.SetNetworkLayerApi(network)

	// Start the command-line interface
	runCLI(network, link)
}

func myPacketHandler(packet *common.IpPacket, networkApi common.NetworkLayerAPI) error {
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
		case "lr":
			listRoutes(network)
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
		case "a":
			handleAccept(parts[1:])
		case "c":
			handleConnect(parts[1:])
		case "ls":
			listSockets(tcpStack)
		case "s":
			handleSend(parts[1:], tcpStack)
		case "r":
			handleReceive(parts[1:], tcpStack)
		case "exit", "q":
			return
		default:
			fmt.Println("Unknown command. Available commands: send, li, ln, lr, exit, q")
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

func listRoutes(network *network_layer.NetworkLayer) {
	fmt.Println("T       Prefix  Next hop   Cost")
	for _, entry := range network.ForwardingTable {
		routeType := ""
		nextHop := ""
		var cost interface{} = entry.Cost // Use interface{} to allow string or int

		switch entry.RoutingType {
		case network_layer.RoutingTypeLocal:
			routeType = "L"
			nextHop = fmt.Sprintf("LOCAL:%s", entry.NextHopIface)
		case network_layer.RoutingTypeRip:
			routeType = "R"
			nextHop = entry.NextHopIP.String()
		case network_layer.RoutingTypeStatic:
			routeType = "S"
			nextHop = entry.NextHopIP.String()
			cost = "-" // Static routes display "-" for cost
		}

		fmt.Printf("%-1s  %11s  %-9s  %4v\n",
			routeType,
			entry.Prefix,
			nextHop,
			cost)
	}
}

func handleConnect(args []string) {
	if len(args) != 2 {
		fmt.Println("Usage: c <ip> <port>")
		return
	}

	destIP, err := netip.ParseAddr(args[0])
	if err != nil {
		fmt.Printf("Invalid IP address: %v\n", err)
		return
	}

	port, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil {
		fmt.Printf("Invalid port number: %v\n", err)
		return
	}

	_, err = tcpStack.Connect(destIP, uint16(port))
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}

	fmt.Printf("Connected to %s:%d\n", destIP, port)
}

func handleAccept(args []string) {
	if len(args) != 1 {
		fmt.Println("Usage: a <port>")
		return
	}

	port, err := strconv.ParseUint(args[0], 10, 16)
	if err != nil {
		fmt.Printf("Invalid port number: %v\n", err)
		return
	}

	socket, err := tcpStack.Listen(uint16(port))
	if err != nil {
		fmt.Printf("Failed to listen: %v\n", err)
		return
	}

	// Accept in a goroutine to not block the CLI
	go func() {
		newSocket, err := socket.Accept()
		if err != nil {
			fmt.Printf("Failed to accept: %v\n", err)
			return
		}
		fmt.Printf("New connection on socket %d => created new socket %d\n",
			socket.ID,
			newSocket.ID)
	}()
}

func listSockets(network *tcp_layer.Tcp) {
	fmt.Println("SID      LAddr LPort       RAddr RPort     Status")

	sockets := network.GetSockets()
	for _, socket := range sockets {
		laddr := socket.LocalAddr.String()
		raddr := socket.RemoteAddr.String()

		fmt.Printf("%-3d  %9s %-6d %10s %-6d    %s\n",
			socket.ID,
			laddr,
			socket.LocalPort,
			raddr,
			socket.RemotePort,
			socket.State)
	}
}

func handleSend(args []string, tcp *tcp_layer.Tcp) {
	if len(args) != 2 {
		fmt.Println("Usage: s <socket ID> <bytes>")
		return
	}

	// Parse socket ID
	socketID, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Printf("Invalid socket ID: %v\n", err)
		return
	}

	// Get the socket
	socket := findSocketByID(tcp, socketID)
	if socket == nil {
		fmt.Printf("Socket %d not found\n", socketID)
		return
	}

	// Check if it's a listen socket
	if socket.State == tcp_layer.LISTEN {
		fmt.Println("Cannot send on listen socket")
		return
	}

	// Send the data from application
	data := []byte(args[1])
	// n, err := socket.VWrite(data)
	_, err = socket.VWrite(data)
	if err != nil {
		fmt.Printf("Send error: %v\n", err)
		return
	}

	// fmt.Printf("VWrite %d bytes\n", n)
}

func handleReceive(args []string, tcp *tcp_layer.Tcp) {
	if len(args) != 2 {
		fmt.Println("Usage: r <socket ID> <numbytes>")
		return
	}

	// Parse socket ID and number of bytes
	socketID, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Printf("Invalid socket ID: %v\n", err)
		return
	}

	numBytes, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Printf("Invalid number of bytes: %v\n", err)
		return
	}

	// Get the socket
	socket := findSocketByID(tcp, socketID)
	if socket == nil {
		fmt.Printf("Socket %d not found\n", socketID)
		return
	}

	// Read the data
	data, err := socket.VRead(numBytes)
	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return
	}

	fmt.Printf("Read %d bytes: %s\n", len(data), string(data))
}

func handleSendFile (args []string, tcp *tcp_layer.Tcp) {
	if len(args) != 3 {
		fmt.Println("Usage: sf <file path> <addr> <port>")
		return
	}
	// first we connect
	destIP, err := netip.ParseAddr(args[1])
	if err != nil {
		fmt.Printf("Invalid IP address: %v\n", err)
		return
	}

	port, err := strconv.ParseUint(args[2], 10, 16)
	if err != nil {
		fmt.Printf("Invalid port number: %v\n", err)
		return
	}

	conn, err := tcpStack.Connect(destIP, uint16(port))
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	// defer conn.close()
	file, err := os.Open(args[0]) 
	if err != nil {
		fmt.Printf("Failed to open file: %v\n", err)
		return
	}
	defer file.Close()

	buf := make([]byte, 1024)
	for {
		n, err := file.Read(buf)
		if err != nil {
			if err == io.EOF {
				break 
			}
			fmt.Printf("Failed to read file: %v\n", err)
			return
		}

		written := 0
		for written < n {
			w, err := conn.Socket.VWrite(buf[written:n]) 
			if w > 0 {
				written += w 
			}
			if err != nil {
				fmt.Printf("Write failed, retrying after delay: %v\n", err)
				time.Sleep(100 * time.Millisecond)
			}
		}
		fmt.Printf("Wrote %d bytes\n", written)
	}
	fmt.Println("File sent successfully.")
}


func findSocketByID(tcp *tcp_layer.Tcp, socketID int) *tcp_layer.Socket {
	sockets := tcp.GetSockets()
	for _, socket := range sockets {
		if socket.ID == socketID {
			return socket
		}
	}
	return nil
}
