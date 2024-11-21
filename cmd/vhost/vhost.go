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
				fmt.Println("Usage: up <interface name>")
				continue
			}
			enableInterface(link, parts[1])
		case "down":
			if len(parts) != 2 {
				fmt.Println("Usage: down <interface name>")
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
		case "cl":
			handleClose(parts[1:], tcpStack)
		case "exit", "q":
			return
		case "sf":
			handleSendFile(parts[1:], tcpStack)
		case "rf":
			handleReceiveFile(parts[1:], tcpStack)
		default:
			fmt.Printf("Invalid command: %s\n"+
				"Commands: \n"+
				"    exit Terminate this program\n"+
				"      li List interfaces\n"+
				"      lr List routes\n"+
				"      ln List available neighbors\n"+
				"      up Enable an interface\n"+
				"    down Disable an interface\n"+
				"    send Send test packet\n"+
				"      ls List sockets\n"+
				"      a Listen on a port and accept new connections\n"+
				"      c Connect to a TCP socket\n"+
				"      s Send on a socket\n"+
				"      r Receive on a socket\n"+
				"     sf Send a file\n"+
				"     rf Receive a file\n"+
				"     cl Close socket\n", parts[0])
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
		_, err := socket.Accept()
		if err != nil {
			fmt.Printf("Failed to accept: %v\n", err)
			return
		}
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
		fmt.Println("Usage: s <socket ID> <data>")
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

func handleSendFile(args []string, tcp *tcp_layer.Tcp) {
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
			time.Sleep(20 * time.Millisecond)
			if w > 0 {
				written += w
			}
			if err != nil {
				// fmt.Printf("Write failed, retrying after delay: %v\n", err)
				time.Sleep(100 * time.Millisecond)
			}
		}
		fmt.Printf("Wrote %d bytes\n", written)
	}
	fmt.Println("File sent successfully.")
	time.Sleep(10 * time.Second)
	for {
		err := tcp.CloseSocket(conn.Socket)
		if  err == nil{
			fmt.Println("conncetion closed")
			break
		}else {
			fmt.Println(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func handleReceiveFile(args []string, tcp *tcp_layer.Tcp) {
	if len(args) != 2 {
		fmt.Println("Usage: sf <filename> <port>")
		return
	}
	port, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil {
		fmt.Printf("Invalid port number: %v\n", err)
		return
	}

	socket, err := tcpStack.Listen(uint16(port))
	if err != nil {
		fmt.Printf("Failed to listen: %v\n", err)
		return
	}
	go func() {
		newSocket, err := socket.Accept()
		if err != nil {
			fmt.Printf("Failed to accept: %v\n", err)
			return
		}

		// err = os.MkdirAll(args[0], 0666) 
		// if err != nil {
		// 	fmt.Printf("Failed to create directories: %v\n", err)
		// 	return
		// }
		outputFile, err := os.Create(args[0])
		if err != nil {
			fmt.Printf("Failed to create file: %v\n", err)
			return
		}
		defer outputFile.Close()

		const readSize = 1024
		for {
			// socket.StateMutex.Lock()
			// if socket.State == tcp_layer.CLOSE_WAIT{
			// 	fmt.Println("Reached EOF")
			// 	socket.StateMutex.Unlock()
			// 	break
			// }
			// socket.StateMutex.Unlock()
			data, err := newSocket.VRead(readSize)
			if err != nil {
				if err == io.EOF{
					fmt.Println("Reached EOF")
					break
				}
				fmt.Printf("Read failed: %v\n", err)
				return
			}
			// Write the received data to the file
			written := 0
			for written < len(data) {
				w, err := outputFile.Write(data[written:])
				if err != nil {
					fmt.Printf("Failed to write to file: %v\n", err)
					return
				}
				written += w
			}
			// fmt.Printf("Wrote %d bytes to file\n", written)
		}
		tcp.CloseSocket(newSocket)
	}()
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

func handleClose(args []string, tcp *tcp_layer.Tcp) {
	if len(args) != 1 {
		fmt.Println("Usage: cl <socket ID>")
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

	// Initiate close
	err = tcp.CloseSocket(socket)
	if err != nil {
		fmt.Printf("Close error: %v\n", err)
	}
}
