use core::net::{IpAddr, Ipv6Addr};

use either::Either;

use crate::{
    iface::{neighbor::CacheOption, NetTx},
    phy::DeviceCaps,
    route::Router,
    socket::{AllSocketSet, SocketRecv, TcpSocketSet, UdpSocketSet},
    stack::RouterExt,
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
    mut packet: Ipv6Packet<Buf<S>>,
) -> SocketRecv<IpPacket<Buf<S>>, ()>
where
    S: Storage,
    R: Router<S>,
    A: AllSocketSet<S>,
{
    let v6_addr = packet.addr;
    let addr = v6_addr.map(IpAddr::V6);

    macro_rules! parse {
        ($payload:expr) => {
            match Ipv6Payload::parse(
                &(device_caps.rx_checksums, packet.next_header),
                $payload,
            ) {
                Ok(payload) => payload,
                Err(err) => log_parse!(err => SocketRecv::NotReceived({
                    packet.payload = err.data;
                    IpPacket::V6(packet)
                })),
            }
        };
    }

    let mut payload = parse!(packet.payload);
    loop {
        break match payload {
            Ipv6Payload::HopByHop(hbh) => match process_hbh(v6_addr, hbh) {
                Ok(p) => {
                    payload = parse!(p);
                    continue;
                }
                Err(Some(buf)) => {
                    packet.payload = buf;
                    icmp_reply(device_caps, v6_addr.reverse(), Icmpv6Packet::ParamProblem {
                        reason: Icmpv6ParamProblem::UnrecognizedOption,
                        pointer: packet.buffer_len() as u32,
                        payload: packet,
                    });
                    SocketRecv::Received(())
                }
                Err(None) => SocketRecv::Received(()),
            },
            Ipv6Payload::Icmp(packet) => {
                process_icmp(now, device_caps, router, hw, v6_addr, packet);
                SocketRecv::Received(())
            }
            Ipv6Payload::Udp(udp) => match sockets.udp().receive(now, device_caps, addr, udp) {
                SocketRecv::Received(()) => SocketRecv::Received(()),
                SocketRecv::NotReceived(mut udp) => SocketRecv::NotReceived({
                    udp.payload.prepend(UDP_HEADER_LEN);
                    packet.payload = udp.payload;
                    IpPacket::V6(packet)
                }),
            },
            Ipv6Payload::Tcp(tcp) => match sockets.tcp().receive(now, device_caps, addr, tcp) {
                SocketRecv::Received(opt) => SocketRecv::Received(opt.map_or((), |(reply, ss)| {
                    let addr = v6_addr.reverse();
                    let cx = &(device_caps.tx_checksums, addr.map(IpAddr::V6));
                    let packet = Ipv6Packet {
                        addr,
                        next_header: IpProtocol::Tcp,
                        hop_limit: 64,
                        payload: uncheck_build!(reply.build(cx)),
                    };

                    // The result is ignored here because it is already recorded in `ss`.
                    let _ = router.dispatch(now, addr.map(Into::into), IpProtocol::Tcp, |_| {
                        Ok::<_, ()>((IpPacket::V6(packet), ss))
                    });
                })),
                SocketRecv::NotReceived(mut tcp) => SocketRecv::NotReceived({
                    tcp.payload.prepend(tcp.header_len());
                    packet.payload = tcp.payload;
                    IpPacket::V6(packet)
                }),
            },
        };
    }
}

fn process_hbh<S>(
    addr: Ends<Ipv6Addr>,
    mut header: Ipv6HopByHopHeader<Buf<S>>,
) -> Result<Buf<S>, Option<Buf<S>>>
where
    S: Storage,
{
    for opt in &header.options {
        match opt {
            Ipv6Opt::Pad1 | Ipv6Opt::PadN(_) | Ipv6Opt::RouterAlert(_) => {}
            &Ipv6Opt::Unknown { option_type, .. } => match Ipv6OptFailureType::from(option_type) {
                Ipv6OptFailureType::Skip => {}
                Ipv6OptFailureType::Discard => return Err(None),
                Ipv6OptFailureType::DiscardSendAll => {
                    header.payload.prepend(header.header_len());
                    return Err(Some(header.payload));
                }
                Ipv6OptFailureType::DiscardSendUnicast if !addr.dst.is_multicast() => {
                    header.payload.prepend(header.header_len());
                    return Err(Some(header.payload));
                }
                _ => unreachable!(),
            },
            _ => {}
        }
    }

    Ok(header.payload)
}

fn process_icmp<S, R>(
    now: Instant,
    device_caps: &DeviceCaps,
    router: &mut R,
    hw: Ends<HwAddr>,
    addr: Ends<Ipv6Addr>,
    packet: Icmpv6Packet<Buf<S>, ReserveBuf<S>>,
) where
    S: Storage,
    R: Router<S>,
{
    match packet {
        Icmpv6Packet::EchoRequest { ident, seq_no, payload }
            if let Some(mut tx) = router.device(now, hw.dst) =>
        {
            let icmp = Icmpv6Packet::EchoReply { ident, seq_no, payload };
            let _ = tx.transmit(now, hw.src, icmp_reply(device_caps, addr.reverse(), icmp));
            return;
        }
        Icmpv6Packet::EchoRequest { .. } | Icmpv6Packet::EchoReply { .. } => {}
        Icmpv6Packet::Nd { nd, payload } => {
            return process_nd(now, device_caps, router, hw, addr, nd, payload)
        }
        Icmpv6Packet::DstUnreachable { .. }
        | Icmpv6Packet::PktTooBig { .. }
        | Icmpv6Packet::TimeExceeded { .. }
        | Icmpv6Packet::ParamProblem { .. } => {}
        _ => {}
    }

    #[cfg(feature = "log")]
    tracing::debug!(
        "ignoring ICMP packet: {:?}",
        packet.substitute(|p| PayloadHolder(p.len()), |_| NoPayloadHolder)
    );
}

fn process_nd<S, R>(
    now: Instant,
    device_caps: &DeviceCaps,
    router: &mut R,
    hw: Ends<HwAddr>,
    addr: Ends<Ipv6Addr>,
    nd: Icmpv6Nd,
    payload: ReserveBuf<S>,
) where
    S: Storage,
    R: Router<S>,
{
    match nd {
        Icmpv6Nd::NeighborSolicit { target_addr, lladdr }
            if let Some(mut dev) = router.device(now, hw.dst) =>
        {
            if let Some(lladdr) = lladdr.and_then(|lladdr| lladdr.parse(&hw.src))
                && (lladdr.is_unicast() && target_addr.is_unicast())
            {
                dev.fill_neighbor_cache(now, (target_addr.into(), lladdr), CacheOption::Override);
            }
            if dev.has_solicited_node(addr.dst) && dev.has_ip(target_addr.into()) {
                let icmp = Icmpv6Packet::Nd {
                    nd: Icmpv6Nd::NeighborAdvert {
                        flags: Icmpv6NeighborFlags::SOLICITED,
                        target_addr,
                        lladdr: Some(dev.hw_addr().into()),
                    },
                    payload,
                };
                let addr = Ends { src: target_addr, dst: addr.src };
                let _ = dev.transmit(now, hw.src, icmp_reply(device_caps, addr, icmp));
            }
        }
        Icmpv6Nd::NeighborSolicit { .. } => {}

        Icmpv6Nd::NeighborAdvert { flags, target_addr, lladdr }
            if let Some(lladdr) = lladdr.and_then(|lladdr| lladdr.parse(&hw.src))
                && (lladdr.is_unicast() && target_addr.is_unicast())
                && let Some(mut dev) = router.device(now, hw.dst) =>
        {
            let opt = if flags.contains(Icmpv6NeighborFlags::OVERRIDE) {
                CacheOption::Override
            } else {
                CacheOption::TryInsert
            };
            dev.fill_neighbor_cache(now, (target_addr.into(), lladdr), opt);
        }
        Icmpv6Nd::NeighborAdvert { .. } => {}

        Icmpv6Nd::RouterSolicit { .. } | Icmpv6Nd::RouterAdvert { .. } => {}
        Icmpv6Nd::Redirect { .. } => {}
    }
}

pub(super) fn icmp_reply<S: Storage>(
    device_caps: &DeviceCaps,
    addr: Ends<Ipv6Addr>,
    icmp: Icmpv6Packet<Buf<S>, ReserveBuf<S>>,
) -> EthernetPayload<Buf<S>, ReserveBuf<S>> {
    let (icmp, buf) = icmp.sub_ref(|b| PayloadHolder(b.len()), |_| NoPayloadHolder);
    let packet_len = icmp.buffer_len();
    let additional = device_caps.header_len + IPV4_HEADER_LEN;

    let icmp = match buf {
        Either::Left(mut buf) => {
            let header_len = packet_len - buf.len();

            if let Some(delta) = (additional + header_len).checked_sub(buf.head_len()) {
                buf.move_truncate(delta as isize);
            }
            icmp.sub_payload(|_| buf)
        }
        Either::Right(buf) => {
            icmp.sub_no_payload(|_| buf.reset().add_reservation(additional + packet_len))
        }
    };

    EthernetPayload::Ip(IpPacket::V6(Ipv6Packet {
        addr,
        next_header: IpProtocol::Icmpv6,
        hop_limit: 64,
        payload: uncheck_build!(icmp.build(&(device_caps.tx_checksums, addr.map(IpAddr::V6)))),
    }))
}
