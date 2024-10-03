# Network Layer Design

## Structures
```go
type IPPacket struct {
    Version    uint8
    IHL        uint8
    TOS        uint8
    TotalLength uint16
    ID         uint16
    Flags      uint8
    FragOffset uint16
    TTL        uint8
    Protocol   uint8
    Checksum   uint16
    SrcIP      net.IP
    DstIP      net.IP
    Options    []byte
    Payload    []byte
}

func (p *IPPacket) ValidateChecksum() bool {
    // Validate the packet's checksum
}

func (p *IPPacket) UpdateTTL() {
    // Decrement TTL and update checksum
}

type ForwardingEntry struct {
    Prefix     string
    PrefixLen  int
    NextHop    string
    Interface  string
}

type ForwardingTable []ForwardingEntry
```

## Global Variables

- **`const networkConfig []IPConfig*`**: Represents the IP configuration of all nodes under the network, parsed using the `lnxconfig` util. After analyzing the data structure returned by the parsing function, it appears that the data is not well decoupled and involves both the Network Layer and Link Layer. To simplify the initial design, both layers will store a copy of this data during initialization.

- **Forwarding Table (`map[string]string`)**: A map where the key is the prefix and the value is the corresponding next-hop.

- **Handler Mapping (`handlerMap`)**: A mapping table created using `make(map[uint8]HandlerFunc)`, which maps protocol numbers to handler functions.

- `interfaces map[string]*net.UDPConn`: Map of interface names to UDP connections

## APIs for Upper Layers

### `func Initialize(configInfo IpConfig) error`
- **Purpose**: 
   1. Initializes the entire network.
   2. Starts a goroutine that runs the RIP algorithm to dynamically update the forwarding table.

### `func SendIP(dst net.IP, protocolNum uint8, data []byte) error`
- **Purpose**: Wraps the data with a network layer header and calls the Link Layer interface to send the data. The current design of this function aims to be generic, allowing it to be used not only as an interface for upper layers but also by the network layer itself when it needs to forward packets.

<!-- ### `type HandlerFunc = func(*Packet, []interface{})` -->
### `func RegisterRecvHandler(protocolNum uint8, callbackFunc HandlerFunc) error`
- **Purpose**: Registers a handler function for a specific protocol number.
   ```go
   if _, exists := handlerMap[protocolNum]; exists {
       return fmt.Errorf("handler for protocol %d already exists", protocolNum)
   }
   handlerMap[protocolNum] = callbackFunc
   return nil
   ```

## Internal Function

### `func HandlePacket(packet *IPPacket)`
- **Purpose**: Handles the received packet based on its protocol number.
- **Code Example**:
   ```go
    func HandlePacket(packet *IPPacket) {
        if !packet.ValidateChecksum() {
            return // Drop packet with invalid checksum
        }
        if packet.TTL == 0 {
            return // Drop packet with expired TTL
        }
        if packet.DstIP.Equal(getOwnIP()) {
            if handler, exists := handlerMap[packet.Protocol]; exists {
                handler(packet)
            }
        } else {
            forwardPacket(packet)
        }
    }
   ```
   
## Helper Functions
```go
func createIPPacket(dst net.IP, protocolNum uint8, data []byte) *IPPacket {
    // Create and return a new IPPacket
}

func findNextHop(dst net.IP) string {
   // ... return NextHop
}

func forwardPacket(packet *IPPacket) {
   packet.UpdateTTL()
   nextHop := findNextHop(packet.DstIP)
   // ... send to Link Layer
}
```

## APIs for Lower Layers (Link Layer)

### `func ReceiveFromLinkLayer(data []byte)`
- **Purpose**: Allows the Link Layer to pass received data to the Network Layer for processing.
- **Code Example**:
    ```go
    func (n *NetworkLayer) ReceiveFromLinkLayer(data []byte) error {
        packet, err := parseIPPacket(data)
        if err != nil {
            return err
        }
        go n.HandlePacket(packet)
        return nil
    }
    ```

---

# Link Layer Design

## Structures
```go
type ARPEntry struct {
    IP  net.IP
    UDP net.UDPAddr
}
```

## Global Variables

<!-- - **`const networkConfig []IPConfig*`**: Contains information related to the ARP protocol, such as the mapping between MAC addresses (UDP ports) and IP addresses. -->
- `arpTable map[string]ARPEntry`: Maps IP addresses to UDP addresses

## APIs for Upper Layers
Since the Link Layer is already the lowest layer, there are no APIs for lower layers.

### `func Initialize(configInfo IpConfig) error`
- **Purpose**:
   1. Initializes the entire network.
   2. Starts a goroutine to listen for incoming UDP packets.

### `func sendPacket(packet *IPPacket, nextHop string)`
- **Purpose**: This function is called by the Network Layer to send a packet to the next hop.

