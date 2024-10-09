package main

import (
	"fmt"
	"net"
)

func main(){
	bindAddr := "127.0.0.1" // Example address and port
	bindPort := "5003"

	// Turn the address string into a UDPAddr for the connection
	bindAddrString := fmt.Sprintf("%s:%s", bindAddr, bindPort)
	bindLocalAddr, err := net.ResolveUDPAddr("udp4", bindAddrString)
	if err != nil {
		fmt.Print(err)
	}

	// Bind on the local UDP port:  this sets the source port
	// and creates a conn
	conn, err := net.ListenUDP("udp4", bindLocalAddr)
	if err != nil {
		fmt.Print(err)
	}
	
	go func(){
		bindAddr := "127.0.0.1" // Example address and port
		bindPort := "5002"
	
		// Turn the address string into a UDPAddr for the connection
		bindAddrString := fmt.Sprintf("%s:%s", bindAddr, bindPort)
		bindLocalAddr, err := net.ResolveUDPAddr("udp4", bindAddrString)
		if err != nil {
			fmt.Print(err)
		}
	
		// Bind on the local UDP port:  this sets the source port
		// and creates a conn
		conn, err := net.ListenUDP("udp4", bindLocalAddr)
		if err != nil {
			fmt.Print(err)
		}
		remoteAddr,_ := net.ResolveUDPAddr("udp4", "127.0.0.1:5003")
		buffer := []byte("hello")
		_, err = conn.WriteToUDP(buffer, remoteAddr)
		if err != nil {
			fmt.Print(err)
		}
	}()


	buffer := make([]byte, 2)
	bytesRead, sourceAddr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Print(err)
	}

	fmt.Printf("Received %d from %s: %s", bytesRead,  sourceAddr.String(), string(buffer))
}