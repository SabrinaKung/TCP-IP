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