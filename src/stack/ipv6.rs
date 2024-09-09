use core::net::{IpAddr, Ipv6Addr};

use either::Either;

use crate::{
    iface::{neighbor::CacheOption, NetTx},
    phy::DeviceCaps,
    route::Router,
    socket::{AllSocketSet, TcpSocketSet, UdpSocketSet},
    time::Instant,
    wire::*,
};

pub(super) fn process<P, R, A>(
    now: Instant,
    device_caps: &DeviceCaps,
    router: &mut R,
    sockets: &mut A,
    hw: Ends<HwAddr>,
    mut packet: Ipv6Packet<P>,
) -> Result<(), IpPacket<P>>
where
    P: PayloadParse + PayloadBuild,
    R: Router<P>,
    A: AllSocketSet<P>,
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
                Err(err) => log_parse!(err => Err({
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
                Err(Some(buf)) if let Some(mut tx) = router.device(now, hw.dst) => {
                    packet.payload = buf;
                    let icmp = Icmpv6Packet::ParamProblem {
                        reason: Icmpv6ParamProblem::UnrecognizedOption,
                        pointer: packet.buffer_len() as u32,
                        payload: Lax(packet),
                    };
                    let addr = v6_addr.reverse();
                    let _ = tx.transmit(now, hw.src, icmp_reply(device_caps, addr, icmp));
                    Ok(())
                }
                Err(_) => Ok(()),
            },
            Ipv6Payload::Icmp(packet) => {
                process_icmp(now, device_caps, router, hw, v6_addr, packet);
                Ok(())
            }
            Ipv6Payload::Udp(udp) => match sockets.udp().receive(now, device_caps, addr, udp) {
                Ok(()) => Ok(()),
                Err(udp) => Err({
                    packet.payload = uncheck_build!(udp.payload.prepend(UDP_HEADER_LEN));
                    IpPacket::V6(packet)
                }),
            },
            Ipv6Payload::Tcp(tcp) => {
                match sockets.tcp().receive(now, device_caps, router, addr, tcp) {
                    Ok(()) => Ok(()),
                    Err(tcp) => Err({
                        let header_len = tcp.header_len();
                        packet.payload = uncheck_build!(tcp.payload.prepend(header_len));
                        IpPacket::V6(packet)
                    }),
                }
            }
        };
    }
}

fn process_hbh<P>(addr: Ends<Ipv6Addr>, header: Ipv6HopByHopHeader<P>) -> Result<P, Option<P>>
where
    P: PayloadBuild,
{
    let header_len = header.header_len();
    for opt in &header.options {
        match opt {
            Ipv6Opt::Pad1 | Ipv6Opt::PadN(_) | Ipv6Opt::RouterAlert(_) => {}
            &Ipv6Opt::Unknown { option_type, .. } => match Ipv6OptFailureType::from(option_type) {
                Ipv6OptFailureType::Skip => {}
                Ipv6OptFailureType::Discard => return Err(None),
                Ipv6OptFailureType::DiscardSendAll => {
                    return Err(Some(uncheck_build!(header.payload.prepend(header_len))));
                }
                Ipv6OptFailureType::DiscardSendUnicast if !addr.dst.is_multicast() => {
                    return Err(Some(uncheck_build!(header.payload.prepend(header_len))));
                }
                _ => unreachable!(),
            },
            _ => {}
        }
    }

    Ok(header.payload)
}

fn process_icmp<P, R>(
    now: Instant,
    device_caps: &DeviceCaps,
    router: &mut R,
    hw: Ends<HwAddr>,
    addr: Ends<Ipv6Addr>,
    packet: Icmpv6Packet<P, P::NoPayload>,
) where
    P: PayloadBuild,
    R: Router<P>,
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

fn process_nd<P, R>(
    now: Instant,
    device_caps: &DeviceCaps,
    router: &mut R,
    hw: Ends<HwAddr>,
    addr: Ends<Ipv6Addr>,
    nd: Icmpv6Nd,
    payload: P::NoPayload,
) where
    P: PayloadBuild,
    R: Router<P>,
{
    match nd {
        Icmpv6Nd::NeighborSolicit { target_addr, lladdr }
            if let Some(mut dev) = router.device(now, hw.dst) =>
        {
            let lladdr = lladdr
                .and_then(|lladdr| lladdr.parse(&hw.src))
                .filter(|lladdr| lladdr.is_unicast() && target_addr.is_unicast());

            if dev.has_solicited_node(addr.dst) && dev.has_ip(target_addr.into()) {
                if let Some(lladdr) = lladdr {
                    dev.fill_neighbor_cache(
                        now,
                        CacheOption::Override,
                        None,
                        (target_addr.into(), lladdr),
                    );
                }

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
            } else if let Some(lladdr) = lladdr {
                dev.fill_neighbor_cache(
                    now,
                    CacheOption::Override,
                    Some(payload),
                    (target_addr.into(), lladdr),
                );
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
            dev.fill_neighbor_cache(now, opt, Some(payload), (target_addr.into(), lladdr));
        }
        Icmpv6Nd::NeighborAdvert { .. } => {}

        Icmpv6Nd::RouterSolicit { .. } | Icmpv6Nd::RouterAdvert { .. } => {}
        Icmpv6Nd::Redirect { .. } => {}
    }
}

pub(super) fn icmp_reply<P: PayloadBuild>(
    device_caps: &DeviceCaps,
    addr: Ends<Ipv6Addr>,
    icmp: Icmpv6Packet<P, P::NoPayload>,
) -> EthernetPayload<P, P::NoPayload> {
    let (icmp, buf) = icmp.sub_ref(|b| PayloadHolder(b.len()), |_| NoPayloadHolder);
    let packet_len = icmp.buffer_len();
    let additional = device_caps.header_len + IPV6_HEADER_LEN;

    let icmp = match buf {
        Either::Left(buf) => icmp.sub_payload(|_| buf),
        Either::Right(buf) => icmp.sub_no_payload(|_| buf.reset().reserve(additional + packet_len)),
    };

    EthernetPayload::Ip(IpPacket::V6(Ipv6Packet {
        addr,
        next_header: IpProtocol::Icmpv6,
        hop_limit: 64,
        payload: uncheck_build!(icmp.build(&(device_caps.tx_checksums, addr.map(IpAddr::V6)))),
    }))
}
