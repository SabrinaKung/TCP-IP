# vhost and vrouter Implementation

This project implements a virtual host (vhost) and a virtual router (vrouter) as part of a network simulation environment. Both programs use a shared network stack implementation to handle IP packet routing and forwarding.

## Components

1. **vhost**: A virtual host implementation that can send and receive packets.
2. **vrouter**: A virtual router implementation that can route packets and implements the RIP (Routing Information Protocol) for dynamic routing.

## Features

Both vhost and vrouter support the following features:

- Sending test packets
- Listing interfaces
- Listing neighbors
- Listing routes
- Enabling/disabling interfaces

Additionally, vrouter implements:

- RIP protocol for dynamic routing
- Periodic RIP updates

## Usage

### Compilation

To compile the programs, use the following commands:

```
go build -o vhost cmd/vhost/vhost.go
go build -o vrouter cmd/vrouter/vrouter.go
```
or simply `make`


### Running

Both programs require a configuration file to be specified:

```
./vhost --config path/to/host_config.lnx
./vrouter --config path/to/router_config.lnx
```

Specify specific topology by running:
```
util/vnet_run [--bin-dir BIN_DIR] lnx_dir
```

### Command-Line Interface

Once running, both vhost and vrouter provide a command-line interface with the following commands:

- `send <destination_ip> <message>`: Send a test packet
- `li`: List interfaces
- `ln`: List neighbors
- `lr`: List routes
- `up <ifname>`: Enable an interface
- `down <ifname>`: Disable an interface
- `exit` or `q`: Exit the program

## Differences between vhost and vrouter

1. **RIP Implementation**: vrouter implements the RIP protocol, while vhost does not.
2. **Periodic Updates**: vrouter sends periodic RIP updates every 5 seconds.
3. **Initialization**: vrouter is initialized with `isRouter` set to true, while vhost sets it to false.

## Implementation Details

- Both programs use a shared network stack implemented in the `network_layer` and `link_layer` packages.
- The network layer handles IP packet routing and forwarding.
- The link layer simulates network interfaces using UDP sockets.
- RIP messages are sent using IP protocol 200.
- The forwarding table is dynamically updated based on received RIP messages in vrouter.



# IP Stack APIs Implementation

## Answers to Key Questions

### 1. How did you build the abstractions for the IP layer and interfaces?

There are two main classes, `NetworkLayer` and `LinkLayer`, defined in their respective packages under the `pkg` directory. These classes provide the API methods to interact with upper or lower layers, along with several helper functions. They also contain fields that store variables required globally during execution. For example, `NetworkLayer` contains the forwarding table, while `LinkLayer` holds interface-related information. These fields are initialized within the respective class' `initialize` method.

The `vhost` and `vrouter` programs directly create instances of these classes, which allow them to call the provided API methods.

### 2. How do you use threads/goroutines?

There are several key areas where goroutines are employed:

1. In the `vrouter` program, a goroutine periodically invokes the `AdvertiseNeighbors` method to send RIP responses to all neighbors.
   
2. During the `NetworkLayer` initialization, a goroutine is started to decrement the lifetime of each forwarding table entry every second.
   
3. In `LinkLayer`, each interface has its own corresponding goroutine.

### 3. What are the steps involved in processing IP packets?

1. The goroutine corresponding to the `LinkLayer` interface receives a UDP packet, extracts the IP packet contained within, and associates the MAC (port) address with the IP address. It then calls the `ReceiveIpPacket(packet *IpPacket, thisHopIp netip.Addr)` API provided by the `NetworkLayer`.
   
2. Once the packet reaches the `NetworkLayer`, the following steps are taken:

   1. TTL is checked.
   2. The checksum is validated.
   3. If the current hop IP matches the destination IP in the packet, the handler function corresponding to the protocol number is called (this function is registered by the user program). If the IP does not match, the packet is forwarded.

## Notable Design Choices

### 1. Dependency Injection

Since the `NetworkLayer` and `LinkLayer` need to call each other’s API functions but cannot have mutual dependencies, I implemented a dependency injection pattern. Each class has an `xxxAPI` field that is an interface defined in the `common` package. For example During the initialization of the `NetworkLayer` class, instances are injected via methods like `SetLinkLayerApi`, where the `LinkLayer` instance is passed into `NetworkLayer`. This design achieves decoupling, making it easier to swap out the implementation of `LinkLayer` in the future by simply passing in a new instance that implements the necessary interface.

### 2. Atomic Integer Usage

After careful consideration, I decided to use atomic integers for the `lifetime` field in the forwarding table entries. By doing this, there's no need to lock the forwarding table. While multiple interfaces may modify the forwarding table concurrently, they will never modify the same entry simultaneously. This is because each prefix has only one exit interface, preventing race conditions.
