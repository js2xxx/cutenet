# `cutenet`: Yet another network stack for Rust

## Design Goals

- **Customizability**: Data structures on every layer of the network stack should be customizable, such as socket sets, routers, network interfaces (e.g. Ethernet, loopback), and physical devices;
- **Portability**: `cutenet` should be able to run as an embedded component, an OS subsystem or a user application library;
- **Performance**: The network stack should be as fast as possible;

## Roadmap

- [x] Packet serialization & deserialization
- [x] Physical devices
- [x] Network interfaces
  - [x] Ethernet interfaces
  - [x] Loopback interfaces
  - [ ] IEEE.802.154 interfaces
- [x] Network IP processing & dispatching
  - [ ] IPv4 fragmentation & reassembly
  - [ ] Multicast groups
- [ ] Network routers
  - [x] Network router trait
  - [x] Static network routers
  - [ ] Dynamic network routers (based on TRIEs)
- [ ] Network sockets
  - [ ] Raw sockets
  - [x] TCP sockets
  - [x] UDP sockets
- [ ] Network socket sets

## References

- [`smoltcp`](https://github.com/smoltcp-rs/smoltcp);
- [`seastar`](https://github.com/scylladb/seastar).