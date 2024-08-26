use core::{net::IpAddr, time::Duration};

use heapless::{Entry, FnvIndexMap};

use super::HwAddr;
use crate::{config::STATIC_NEIGHBOR_CACHE_CAPACITY, time::Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NeighborLookupError {
    pub rate_limited: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NeighborCacheOption {
    Override,
    TryInsert,
    UpdateExpiration,
}

#[derive(Debug)]
struct Neighbor {
    hw: HwAddr,
    expiration: Instant,
}

#[derive(Debug)]
pub struct StaticNeighborCache {
    map: FnvIndexMap<IpAddr, Neighbor, STATIC_NEIGHBOR_CACHE_CAPACITY>,
    silent_until: Instant,
}

impl StaticNeighborCache {
    pub const EXPIRATION: Duration = Duration::from_secs(1200);

    pub const SILENT_PERIOD: Duration = Duration::from_secs(1);

    pub const fn new() -> Self {
        Self {
            map: FnvIndexMap::new(),
            silent_until: Instant::ZERO,
        }
    }

    pub fn fill(&mut self, now: Instant, (ip, hw): (IpAddr, HwAddr), opt: NeighborCacheOption) {
        use NeighborCacheOption::*;

        let expiration = now + Self::EXPIRATION;
        match (self.map.entry(ip), opt) {
            (Entry::Occupied(ent), Override) => {
                ent.insert(Neighbor { hw, expiration });
            }

            (Entry::Occupied(mut ent), UpdateExpiration) if ent.get().hw == hw => {
                ent.get_mut().expiration = expiration
            }

            (Entry::Vacant(ent), Override | TryInsert) => {
                match ent.insert(Neighbor { hw, expiration }) {
                    Ok(_) => {}
                    Err(neighbor) => {
                        let (&old_ip, _) = self
                            .map
                            .iter_mut()
                            .min_by_key(|(_, n)| n.expiration)
                            .unwrap();

                        self.map.remove(&old_ip);
                        let _res = self.map.insert(ip, neighbor);
                        debug_assert!(_res.is_ok());
                    }
                }
            }

            (Entry::Occupied(_), TryInsert | UpdateExpiration)
            | (Entry::Vacant(_), UpdateExpiration) => {}
        }
    }

    pub fn lookup(&self, now: Instant, ip: IpAddr) -> Result<HwAddr, NeighborLookupError> {
        match self.map.get(&ip) {
            Some(neighbor) if neighbor.expiration > now => Ok(neighbor.hw),
            _ => Err(NeighborLookupError {
                rate_limited: self.silent_until > now,
            }),
        }
    }

    pub fn silent(&mut self, now: Instant) {
        self.silent_until = now + Self::SILENT_PERIOD;
    }

    pub fn flush(&mut self) {
        self.map.clear();
    }
}

impl Default for StaticNeighborCache {
    fn default() -> Self {
        Self::new()
    }
}
