use core::net::{IpAddr, Ipv4Addr};

use crate::{
    iface::NetTx,
    phy::DeviceCaps,
    route::Router,
    socket::{AllSocketSet, SocketSet},
    storage::{PayloadBuild, PayloadHolder, PayloadParse},
    time::Instant,
    wire::*,
};

pub(super) fn process<P, R, A>(
    now: Instant,
    device_caps: &DeviceCaps,
    router: &mut R,
    sockets: &mut A,
    hw: Ends<HwAddr>,
    mut packet: Ipv4Packet<P>,
) -> Result<(), IpPacket<P>>
where
    P: PayloadParse + PayloadBuild,
    R: Router<P>,
    A: AllSocketSet<P>,
{
    let v4_addr = packet.addr;
    let addr = v4_addr.map(IpAddr::V4);

    let payload = match Ipv4Payload::parse(
        &(device_caps.rx_checksums, packet.next_header),
        packet.payload,
    ) {
        Ok(payload) => payload,
        Err(err) => log_parse!(err => Err({
            packet.payload = err.data;
            IpPacket::V4(packet)
        })),
    };

    match payload {
        Ipv4Payload::Icmp(packet) => {
            process_icmp(now, device_caps, router, hw, v4_addr, packet);
            Ok(())
        }
        Ipv4Payload::Udp(udp) => match sockets.udp().receive(now, device_caps, router, addr, udp) {
            Ok(()) => Ok(()),
            Err(udp) => {
                packet.payload = uncheck_build!(udp.payload.prepend(UDP_HEADER_LEN));
                Err(IpPacket::V4(packet))
            }
        },
        Ipv4Payload::Tcp(tcp) => match sockets.tcp().receive(now, device_caps, router, addr, tcp) {
            Ok(()) => Ok(()),
            Err(tcp) => {
                let header_len = tcp.header_len();
                packet.payload = uncheck_build!(tcp.payload.prepend(header_len));
                Err(IpPacket::V4(packet))
            }
        },
    }
}

fn process_icmp<P, R>(
    now: Instant,
    device_caps: &DeviceCaps,
    router: &mut R,
    hw: Ends<HwAddr>,
    addr: Ends<Ipv4Addr>,
    packet: Icmpv4Packet<P>,
) where
    P: PayloadBuild,
    R: Router<P>,
{
    match packet {
        Icmpv4Packet::EchoRequest { ident, seq_no, payload }
            if let Some(mut tx) = router.device(now, hw.dst) =>
        {
            let icmp = Icmpv4Packet::EchoReply { ident, seq_no, payload };
            let _ = tx.transmit(now, hw.src, icmp_reply(device_caps, addr.reverse(), icmp));
            return;
        }
        Icmpv4Packet::EchoRequest { .. } | Icmpv4Packet::EchoReply { .. } => return,
        Icmpv4Packet::DstUnreachable { .. } | Icmpv4Packet::TimeExceeded { .. } => {}
        _ => {}
    }

    #[cfg(feature = "log")]
    tracing::debug!(
        "ignoring ICMP packet: {:?}",
        packet.sub_payload(|p| PayloadHolder(p.len()))
    );
}

pub(super) fn icmp_reply<P>(
    device_caps: &DeviceCaps,
    addr: Ends<Ipv4Addr>,
    icmp: Icmpv4Packet<P>,
) -> EthernetPayload<P, P::NoPayload>
where
    P: PayloadBuild,
{
    let (icmp, buf) = icmp.sub_payload_ref(|b| PayloadHolder(b.len()));

    EthernetPayload::Ip(IpPacket::V4(Ipv4Packet {
        addr,
        next_header: IpProtocol::Icmp,
        hop_limit: 64,
        frag_info: None,
        payload: uncheck_build!(icmp
            .sub_payload(|_| buf)
            .build(&(device_caps.tx_checksums, addr.map(IpAddr::V4)))),
    }))
}
