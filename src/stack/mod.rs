use core::{marker::PhantomData, net::IpAddr};

use self::icmp::Icmp;
use crate::{
    iface::{neighbor::CacheOption, NetRx, NetTx},
    phy::DeviceCaps,
    route::{Action, Query, Router},
    socket::{AllSocketSet, RawSocketSet},
    time::Instant,
    wire::*,
    TxDropReason, TxResult,
};

mod arp;
mod icmp;
mod ipv4;
mod ipv6;

pub fn process<P, R, Rx, A>(
    mut router: R,
    now: Instant,
    mut rx: Rx,
    mut sockets: A,
) -> Option<TxResult>
where
    P: PayloadBuild + PayloadParse,
    R: Router<P>,
    Rx: NetRx<P>,
    A: AllSocketSet<P>,
{
    // 1. Receive the packet.
    let (src_hw, payload) = rx.receive(now)?;
    let hw = rx.hw_addr();
    let device_caps = rx.device_caps();
    drop(rx);

    // 2. Handle the ARP packet.
    let packet = match payload {
        EthernetPayload::Arp(packet) => {
            let res = self::arp::process_arp(now, &mut router, hw, packet);
            return Some(res.unwrap_or(TxResult::Success));
        }
        EthernetPayload::Ip(packet) => packet,
    };

    // 3. Route the IP packet (external input).
    let addr = packet.ip_addr();
    let action = match router.route(now, Query {
        addr,
        next_header: packet.next_header(),
    }) {
        Action::Deliver { .. } => Action::Deliver { loopback: () },

        // 3.1 Forward the external IP packet.
        Action::Forward { next_hop, mut tx } => {
            let mut packet = packet;
            return Some(if packet.decrease_hop_limit() {
                match transmit(now, addr, next_hop, tx) {
                    Ok(tx) => tx.comsume(now, packet),
                    Err(err) => TxResult::Dropped(match err {
                        DispatchError::NoRoute => TxDropReason::NoRoute,
                        DispatchError::NeighborPending => TxDropReason::NeighborPending,
                    }),
                }
            } else {
                let packet = Icmp::HopLimitExceeded(packet).build(&tx.device_caps());
                tx.transmit(now, src_hw, packet)
            });
        }
        Action::Discard => Action::Discard,
    };

    if let Some(mut tx) = router.device(now, hw) {
        tx.fill_neighbor_cache(now, CacheOption::UpdateExpiration, None, (addr.src, src_hw));

        match action {
            Action::Deliver { .. } => {}
            Action::Forward { tx: (), .. } => unreachable!(),

            // 3.2 Discard the external IP packet.
            Action::Discard => {
                let packet = Icmp::NoRoute(packet).build(&tx.device_caps());
                return Some(tx.transmit(now, src_hw, packet));
            }
        }
    } else {
        match action {
            Action::Deliver { .. } => {}
            Action::Forward { tx: (), .. } => unreachable!(),
            Action::Discard => return Some(TxResult::Success),
        }
    }
    // 3.3 Deliver the external IP packet to the upper layer.

    // 4.1 Offer the IP packet to raw sockets.
    let raw_processed = sockets.raw().receive(now, &device_caps, &packet);

    // 4.2 Offer the IP packet to general sockets.
    let hw = Ends { src: src_hw, dst: hw };
    let res = match packet {
        IpPacket::V4(packet) => {
            ipv4::process(now, &device_caps, &mut router, &mut sockets, hw, packet)
        }
        IpPacket::V6(packet) => {
            ipv6::process(now, &device_caps, &mut router, &mut sockets, hw, packet)
        }
    };

    if let Err(packet) = res
        && !raw_processed
        && let Some(mut tx) = router.device(now, hw.dst)
    {
        let packet = Icmp::NoProtocol(packet).build(&tx.device_caps());
        let _ = tx.transmit(now, src_hw, packet);
    }
    Some(TxResult::Success)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DispatchError {
    NoRoute,
    NeighborPending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackTx<P, Tx> {
    tx: Tx,
    dst: HwAddr,
    payload: PhantomData<fn(P)>,
}

impl<P: Payload, Tx: NetTx<P>> StackTx<P, Tx> {
    fn new(tx: Tx, dst: HwAddr) -> Self {
        Self { tx, dst, payload: PhantomData }
    }

    pub fn device_caps(&self) -> DeviceCaps {
        self.tx.device_caps()
    }

    pub fn comsume(mut self, now: Instant, packet: IpPacket<P>) -> TxResult {
        self.tx.transmit(now, self.dst, EthernetPayload::Ip(packet))
    }
}

pub fn dispatch<P, R>(
    router: &mut R,
    now: Instant,
    addr: Ends<IpAddr>,
    next_header: IpProtocol,
) -> Result<StackTx<P, R::Tx<'_>>, DispatchError>
where
    P: PayloadBuild,
    R: Router<P>,
{
    match router.route(now, Query { addr, next_header }) {
        Action::Deliver { loopback } => Ok(StackTx::new(loopback, HwAddr::Ip)),
        Action::Forward { next_hop, tx } => transmit(now, addr, next_hop, tx),
        Action::Discard => Err(DispatchError::NoRoute),
    }
}

fn lookup_hw<P, Tx>(
    now: Instant,
    ip: Ends<IpAddr>,
    next_hop: IpAddr,
    tx: &mut Tx,
) -> Result<HwAddr, Option<P::NoPayload>>
where
    P: PayloadBuild,
    Tx: NetTx<P>,
{
    let hw = tx.hw_addr();
    if hw == HwAddr::Ip {
        return Ok(HwAddr::Ip);
    }

    if tx.is_broadcast(ip.dst) {
        let dst = match hw {
            HwAddr::Ethernet(_) => HwAddr::Ethernet(EthernetAddr::BROADCAST),
            HwAddr::Ieee802154(_) => HwAddr::Ieee802154(Ieee802154Addr::BROADCAST),
            HwAddr::Ip => unreachable!(),
        };
        return Ok(dst);
    }

    if ip.dst.is_multicast() {
        let dst = match hw {
            HwAddr::Ethernet(_) => HwAddr::Ethernet(ip.dst.multicast_ethernet()),
            HwAddr::Ieee802154(_) => HwAddr::Ieee802154(Ieee802154Addr::BROADCAST),
            HwAddr::Ip => unreachable!(),
        };
        return Ok(dst);
    }

    tx.lookup_neighbor_cache(now, next_hop)
}

fn transmit<P, Tx>(
    now: Instant,
    ip: Ends<IpAddr>,
    next_hop: IpAddr,
    mut tx: Tx,
) -> Result<StackTx<P, Tx>, DispatchError>
where
    P: PayloadBuild,
    Tx: NetTx<P>,
{
    let buf = match lookup_hw(now, ip, next_hop, &mut tx) {
        Ok(dst) => return Ok(StackTx::new(tx, dst)),
        Err(None) => return Err(DispatchError::NeighborPending),
        Err(Some(nop)) => nop,
    };

    let hw = tx.hw_addr();
    let buf = buf.reset();

    match (ip.src, ip.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let packet = ArpPacket {
                operation: ArpOperation::Request,
                addr: Ends {
                    src: (hw.unwrap_ethernet(), src),
                    dst: (EthernetAddr::BROADCAST, dst),
                },
                payload: NoPayloadHolder,
            };

            let buf = buf.reserve(packet.buffer_len() + tx.device_caps().header_len);
            let packet = packet.sub_no_payload(|_| buf);

            let _ = tx.transmit(
                now,
                EthernetAddr::BROADCAST.into(),
                EthernetPayload::Arp(packet),
            );
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let dst = dst.solicited_node();

            let packet = ipv6::icmp_reply(&tx.device_caps(), Ends { src, dst }, Icmpv6Packet::Nd {
                nd: Icmpv6Nd::NeighborSolicit {
                    target_addr: dst,
                    lladdr: Some(hw.into()),
                },
                payload: buf,
            });

            let hw_dst = match hw {
                HwAddr::Ethernet(_) => HwAddr::Ethernet(dst.multicast_ethernet()),
                HwAddr::Ieee802154(_) => HwAddr::Ieee802154(Ieee802154Addr::BROADCAST),
                HwAddr::Ip => unreachable!(),
            };

            let _ = tx.transmit(now, hw_dst, packet);
        }
        _ => unreachable!(),
    }
    Err(DispatchError::NeighborPending)
}
