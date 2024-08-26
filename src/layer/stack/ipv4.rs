use core::net::{IpAddr, Ipv4Addr};

use super::dispatch_impl;
use crate::{
    context::Ends,
    layer::{
        iface::NetTx,
        phy::DeviceCaps,
        route::Router,
        socket::{AllSocketSet, SocketRecv, TcpSocketSet, UdpSocketSet},
    },
    storage::{Buf, ReserveBuf, Storage},
    time::Instant,
    wire::*,
};

pub(super) fn process<S, R, A>(
    now: Instant,
    device_caps: &DeviceCaps,
    router: &mut R,
    sockets: &mut A,
    hw: Ends<HwAddr>,
    mut packet: Ipv4Packet<Buf<S>>,
) -> SocketRecv<IpPacket<Buf<S>>, ()>
where
    S: Storage,
    R: Router<S>,
    A: AllSocketSet<S>,
{
    let addr = packet.addr;

    let payload = match Ipv4Payload::parse(
        &(device_caps.rx_checksums, packet.next_header),
        packet.payload,
    ) {
        Ok(payload) => payload,
        Err(err) => log_parse!(err => SocketRecv::NotReceived({
            packet.payload = err.data;
            IpPacket::V4(packet)
        })),
    };

    match payload {
        Ipv4Payload::Icmp(packet) => {
            process_icmp(now, device_caps, router, hw, addr, packet);
            SocketRecv::Received { reply: () }
        }
        Ipv4Payload::Udp(udp) => {
            let mut sockets = sockets.udp();
            match sockets.receive(now, device_caps, addr.map(Into::into), udp) {
                SocketRecv::Received { reply: () } => SocketRecv::Received { reply: () },
                SocketRecv::NotReceived(mut udp) => SocketRecv::NotReceived({
                    udp.payload.prepend(UDP_HEADER_LEN);
                    packet.payload = udp.payload;
                    IpPacket::V4(packet)
                }),
            }
        }
        Ipv4Payload::Tcp(tcp) => {
            let mut sockets = sockets.tcp();
            match sockets.receive(now, device_caps, addr.map(Into::into), tcp) {
                SocketRecv::Received { reply: Some(reply) } => {
                    let addr = addr.reverse();
                    let cx = &(device_caps.tx_checksums, addr.map(IpAddr::V4));
                    let packet = Ipv4Packet {
                        addr,
                        next_header: IpProtocol::Tcp,
                        hop_limit: 64,
                        frag_info: None,
                        payload: uncheck_build!(reply.build(cx)),
                    };

                    dispatch_impl(now, router, IpPacket::V4(packet));
                    SocketRecv::Received { reply: () }
                }
                SocketRecv::Received { reply: None } => SocketRecv::Received { reply: () },
                SocketRecv::NotReceived(mut tcp) => SocketRecv::NotReceived({
                    tcp.payload.prepend(tcp.buffer_len() - tcp.payload_len());
                    packet.payload = tcp.payload;
                    IpPacket::V4(packet)
                }),
            }
        }
    }
}

fn process_icmp<S, R>(
    now: Instant,
    device_caps: &DeviceCaps,
    router: &mut R,
    hw: Ends<HwAddr>,
    addr: Ends<Ipv4Addr>,
    packet: Icmpv4Packet<Buf<S>>,
) where
    S: Storage,
    R: Router<S>,
{
    match packet {
        Icmpv4Packet::EchoRequest { ident, seq_no, payload }
            if let Some(mut tx) = router.device(now, hw.dst) =>
        {
            let icmp = Icmpv4Packet::EchoReply { ident, seq_no, payload };
            return tx.transmit(now, hw.src, icmp_reply(device_caps, addr.reverse(), icmp));
        }
        Icmpv4Packet::EchoRequest { .. } | Icmpv4Packet::EchoReply { .. } => return,
        Icmpv4Packet::DstUnreachable { .. } => {}
        Icmpv4Packet::TimeExceeded { .. } => {}
    }

    #[cfg(feature = "log")]
    tracing::debug!(
        "ignoring ICMP packet: {:?}",
        packet.sub_payload(|p| PayloadHolder(p.len()))
    );
}

pub(super) fn icmp_reply<S: Storage>(
    device_caps: &DeviceCaps,
    addr: Ends<Ipv4Addr>,
    icmp: Icmpv4Packet<Buf<S>>,
) -> EthernetPayload<Buf<S>, ReserveBuf<S>> {
    let (icmp, mut buf) = icmp.sub_payload_ref(|b| PayloadHolder(b.len()));
    let packet_len = icmp.buffer_len();
    let header_len = packet_len - buf.len();

    if let Some(delta) = (IPV4_HEADER_LEN + header_len).checked_sub(buf.head_len()) {
        buf.move_truncate(delta as isize);
    }

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
