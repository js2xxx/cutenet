# `cutenet`: Yet another network stack for Rust

## Roadmap

- [x] Packet serialization & deserialization
- [x] Physical devices
- [x] Network interfaces
  - [x] Ethernet interfaces
  - [x] Loopback interfaces
  - [ ] IEEE.802.154 interfaces
- [x] Network IP processing & dispatching
  - [ ] IPv4 fragmentation & reassembly
- [ ] Network routers
  - [x] Network router trait
  - [ ] Static network routers
  - [ ] Dynamic network routers (based on TRIEs)
- [ ] Network sockets
  - [ ] Raw sockets
  - [ ] TCP sockets
  - [ ] UDP sockets
- [ ] Network socket sets

## References

- [`smoltcp`](https://github.com/smoltcp-rs/smoltcp).