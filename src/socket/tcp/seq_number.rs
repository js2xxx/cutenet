use core::{
    hash::BuildHasher,
    net::{IpAddr, SocketAddr},
};

use super::TcpListener;
use crate::{time::Instant, wire::*};

// Alcock, Shane and Richard Nelson. “An Analysis of TCP Maximum Segment Sizes.”
// (2010).
const MSS_TABLE: [u16; 4] = [
    536, 1300, 1440, // 1440, 1452: PPPoE
    1460,
];

const MSS_OFFSET: u32 = 16;
const SACK_OFFSET: u32 = 18;
const TIME_OFFSET: u32 = 20;

const MSS_MASK: u32 = 3;
const SACK_MASK: u32 = 1;
const TIME_MASK: u32 = 15;

const HASH_MASK: u32 =
    !0 - (MSS_MASK << MSS_OFFSET) - (SACK_MASK << SACK_OFFSET) - (TIME_MASK << TIME_OFFSET);

fn time_period(time: Instant) -> u32 {
    (time.secs() / 64) as u32 & TIME_MASK
}

impl<Rx, H: BuildHasher> TcpListener<Rx, H> {
    pub(super) fn seq_number<P: Payload>(
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

        let sack_permitted = u32::from(packet.sack_permitted);

        let hash1 = self.seq_hasher.hash_one(addr) as u32;
        let hash2 = self.seq_hasher.hash_one((addr, time_period)) as u32;

        let seq = ((hash2 & HASH_MASK)
            + (mss_index << MSS_OFFSET)
            + (sack_permitted << SACK_OFFSET)
            + (time_period << TIME_OFFSET))
            ^ hash1;

        TcpSeqNumber(seq)
    }

    pub(super) fn check_seq_number<P: Payload>(
        &self,
        now: Instant,
        ip: Ends<IpAddr>,
        packet: &TcpPacket<P>,
    ) -> Option<(u16, bool)> {
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
        let sack_permitted = (data >> SACK_OFFSET) & SACK_MASK != 0;
        MSS_TABLE
            .get(mss_index as usize)
            .copied()
            .map(|mss| (mss, sack_permitted))
    }
}
