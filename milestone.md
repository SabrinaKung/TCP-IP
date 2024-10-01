



# Network Layer Design

## Global Variables

- **`const networkConfig []IPConfig*`**: Represents the IP configuration of all nodes under the network, parsed using the `lnxconfig` util. After analyzing the data structure returned by the parsing function, it appears that the data is not well decoupled and involves both the Network Layer and Link Layer. To simplify the initial design, both layers will store a copy of this data during initialization.

- **Forwarding Table (`map[string]string`)**: A map where the key is the prefix and the value is the corresponding next-hop.

- **Handler Mapping (`handlerMap`)**: A mapping table created using `make(map[uint8]HandlerFunc)`, which maps protocol numbers to handler functions.

## APIs for Upper Layers

### `func Initialize(configInfo IpConfig) error`
- **Purpose**: 
   1. Initializes the entire network.
   2. Starts a goroutine that runs the RIP algorithm to dynamically update the forwarding table.

### `func SendIP(dst netip.Addr, protocolNum uint8, data []byte) error`
- **Purpose**: Wraps the data with a network layer header and calls the Link Layer interface to send the data. The current design of this function aims to be generic, allowing it to be used not only as an interface for upper layers but also by the network layer itself when it needs to forward packets.

### `type HandlerFunc = func(*Packet, []interface{})`
### `func RegisterRecvHandler(protocolNum uint8, callbackFunc HandlerFunc) error`
- **Purpose**: Registers a handler function for a specific protocol number.
   ```go
   if _, exists := handlerMap[protocolNum]; exists {
       return fmt.Errorf("handler for protocol %d already exists", protocolNum)
   }
   handlerMap[protocolNum] = callbackFunc
   return nil
   ```

### `func HandlePacket(packet *Packet)`
- **Purpose**: Handles the received packet based on its protocol number.
- **Code Example**:
   ```go
   protocolNum := packet.Protocol

   if handler, exists := handlerMap[protocolNum]; exists {
       handler(packet, []interface{}{})
   } else {
       fmt.Printf("No handler found for that protocol")
   }
   ```

## APIs for Lower Layers (Link Layer)

### `func ReceivePacket(packet *Packet)`
- **Purpose**: Allows the Link Layer to notify the Network Layer when an IP packet is received. This function includes various network layer tasks, such as validating the checksum, confirming the TTL, and deciding whether to forward the packet or process it using the `HandlePacket` logic.

---

# Link Layer Design

## Global Variables

- **`const networkConfig []IPConfig*`**: Contains information related to the ARP protocol, such as the mapping between MAC addresses (UDP ports) and IP addresses.

## APIs for Upper Layersd
Since the Link Layer is already the lowest layer, there are no APIs for lower layers.

### `func Initialize(configInfo IpConfig) error`
- **Purpose**:
   1. Initializes the entire network.
   2. Starts a goroutine to listen for incoming UDP packets.

### `func sendPacket(packet *Packet, nextHop string)`
- **Purpose**: This function is called by the Network Layer to send a packet to the next hop.

