use core::{
    hash::BuildHasher,
    net::{IpAddr, SocketAddr},
};

use super::{TcpListener, TcpStream};
use crate::{socket::SocketRx, time::Instant, wire::*};

// Alcock, Shane and Richard Nelson. “An Analysis of TCP Maximum Segment Sizes.”
// (2010).
const MSS_TABLE: [u16; 4] = [
    536, 1300, 1440, // 1440, 1452: PPPoE
    1460,
];

const MSS_OFFSET: u32 = 16;
const TIME_OFFSET: u32 = 20;

const MSS_MASK: u32 = 3;
const TIME_MASK: u32 = 15;

const HASH_MASK: u32 = !0 - (MSS_MASK << MSS_OFFSET) - (TIME_MASK << TIME_OFFSET);

fn time_period(time: Instant) -> u32 {
    (time.secs() / 64) as u32 & TIME_MASK
}

impl<P, Rx, H> TcpListener<P, Rx, H>
where
    P: Payload,
    Rx: SocketRx<Item = TcpStream<P>>,
    H: BuildHasher,
{
    pub(super) fn seq_number(
        &self,
        now: Instant,
        ip: Ends<IpAddr>,
        packet: &TcpPacket<P>,
    ) -> TcpSeqNumber {
        let addr = ip.zip_map(packet.port, SocketAddr::new);
        let time_period = time_period(now);

        let mss_index = match packet.max_seg_size {
            Some(mss) => MSS_TABLE.iter().rposition(|&x| x <= mss).unwrap_or(0),
            None => MSS_TABLE.len() - 1,
        } as u32;

        let hash1 = self.seq_hasher.hash_one(addr) as u32;
        let hash2 = self.seq_hasher.hash_one((addr, time_period)) as u32;

        let seq = hash1
            ^ ((hash2 & HASH_MASK) + (mss_index << MSS_OFFSET) + (time_period << TIME_OFFSET));

        TcpSeqNumber(seq)
    }

    pub(super) fn check_seq_number(
        &self,
        now: Instant,
        ip: Ends<IpAddr>,
        packet: &TcpPacket<P>,
    ) -> Option<u16> {
        let addr = ip.zip_map(packet.port, SocketAddr::new);
        let time_period = time_period(now);

        let seq = packet.ack_number?.0;

        let hash1 = self.seq_hasher.hash_one(addr) as u32;
        let hash2 = self.seq_hasher.hash_one((addr, time_period)) as u32;

        let data = (seq ^ hash1) - (hash2 & HASH_MASK);
        if data & HASH_MASK != 0 {
            return None;
        }

        let packet_time_period = (seq >> TIME_OFFSET) & TIME_MASK;
        if packet_time_period != time_period {
            return None;
        }

        let mss_index = (data >> MSS_OFFSET) & MSS_MASK;
        MSS_TABLE.get(mss_index as usize).copied()
    }
}
