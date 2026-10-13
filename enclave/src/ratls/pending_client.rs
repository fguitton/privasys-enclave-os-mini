//! Paid transport bytes before the original ClientHello parser. No authority.
use enclave_os_common::{
    allocation::{bounded_vec_capacity, AllocationLeaseV1, AllocationPoolV1},
    channel::MAX_CHANNEL_PAYLOAD,
};
use std::sync::Arc;

/// Original incomplete-ClientHello policy; checked only after parsing.
pub(crate) const MAX_PENDING_CLIENTHELLO: usize = 16 * 1024;

pub(crate) struct PendingClientHello {
    peer_addr: String,
    buffered: Vec<u8>,
    _peer_allocation: Option<AllocationLeaseV1>,
    buffer_allocation: Option<AllocationLeaseV1>,
    pool: Option<Arc<AllocationPoolV1>>,
}
impl PendingClientHello {
    pub(crate) fn new(peer: &[u8]) -> Result<Self, &'static str> {
        #[cfg(target_env = "sgx")]
        let pool = Some(crate::local_allocation_pool().ok_or("SDK heap unavailable")?);
        #[cfg(not(target_env = "sgx"))]
        let pool = None;
        Self::admitted(peer, pool)
    }
    pub(super) fn admitted(
        peer: &[u8],
        pool: Option<Arc<AllocationPoolV1>>,
    ) -> Result<Self, &'static str> {
        if peer.len() > MAX_CHANNEL_PAYLOAD {
            return Err("peer address exceeds channel bound");
        }
        let peer = core::str::from_utf8(peer).unwrap_or("<invalid>");
        let allocation = Self::reserve(peer.len(), pool.as_ref())?;
        let mut peer_addr = String::new();
        peer_addr
            .try_reserve_exact(peer.len())
            .map_err(|_| "peer address allocation failed")?;
        if peer_addr.capacity() != peer.len() {
            drop(peer_addr);
            return Err("peer address capacity differs from admission");
        }
        peer_addr.push_str(peer);
        if let Some(credit) = &allocation {
            credit.activate_release_notification();
        }
        Ok(Self {
            peer_addr,
            buffered: Vec::new(),
            _peer_allocation: allocation,
            buffer_allocation: None,
            pool,
        })
    }
    fn reserve(
        bytes: usize,
        pool: Option<&Arc<AllocationPoolV1>>,
    ) -> Result<Option<AllocationLeaseV1>, &'static str> {
        // Empty String/Vec has no child backing; original empty peer input
        // must not become a zero-byte physical reservation refusal.
        if bytes == 0 {
            return Ok(None);
        }
        pool.map(|pool| {
            pool.reserve_unpublished(bytes)
                .ok_or("pending ClientHello admission exhausted")
        })
        .transpose()
    }
    pub(crate) fn peer_addr(&self) -> &str {
        &self.peer_addr
    }
    pub(crate) fn buffered(&self) -> &[u8] {
        &self.buffered
    }
    pub(crate) fn append(&mut self, input: &[u8]) -> Result<(), &'static str> {
        // A complete final channel chunk may exceed the incomplete policy.
        // Preserve that route: bound the previous incomplete bytes plus one
        // genuinely bounded channel payload, and parse before policy refusal.
        if input.len() > MAX_CHANNEL_PAYLOAD || self.buffered.len() > MAX_PENDING_CLIENTHELLO {
            return Err("pending ClientHello channel geometry invalid");
        }
        let maximum = MAX_PENDING_CLIENTHELLO
            .checked_add(MAX_CHANNEL_PAYLOAD)
            .ok_or("pending ClientHello maximum overflow")?;
        let required = self
            .buffered
            .len()
            .checked_add(input.len())
            .ok_or("pending ClientHello length overflow")?;
        if required > self.buffered.capacity() {
            let capacity = bounded_vec_capacity(required, maximum)
                .ok_or("pending ClientHello capacity overflow")?;
            // Keep old backing paid while reallocating the new full backing.
            let allocation = Self::reserve(capacity, self.pool.as_ref())?;
            self.buffered
                .try_reserve_exact(capacity - self.buffered.len())
                .map_err(|_| "pending ClientHello allocation failed")?;
            if self.buffered.capacity() != capacity {
                drop(core::mem::take(&mut self.buffered));
                drop(self.buffer_allocation.take());
                return Err("pending ClientHello capacity differs from admission");
            }
            drop(core::mem::replace(&mut self.buffer_allocation, allocation));
            if let Some(credit) = &self.buffer_allocation {
                credit.activate_release_notification();
            }
        }
        self.buffered.extend_from_slice(input);
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn check() {
    let occupied = AllocationPoolV1::new(1).unwrap();
    let blocker = occupied.reserve_unpublished(1).unwrap();
    let mut empty = PendingClientHello::admitted(b"", Some(Arc::clone(&occupied))).unwrap();
    assert_eq!(empty.peer_addr(), "");
    empty.append(&[]).unwrap();
    assert!(empty.buffered().is_empty());
    assert_eq!(
        occupied.used(),
        1,
        "no backing allocated for empty peer/input"
    );
    drop(empty);
    assert_eq!(occupied.used(), 1);
    drop(blocker);
    assert_eq!(occupied.used(), 0);
    eprintln!("PENDING-EMPTY-PEER: original empty input needs no physical child allocation PASS");
    let peer = b"peer";
    let small = AllocationPoolV1::new(peer.len() - 1).unwrap();
    assert!(PendingClientHello::admitted(peer, Some(Arc::clone(&small))).is_err());
    assert_eq!(small.used(), 0);
    for allowance in [peer.len(), peer.len() + 1] {
        let pool = AllocationPoolV1::new(allowance).unwrap();
        let pending = PendingClientHello::admitted(peer, Some(Arc::clone(&pool))).unwrap();
        assert_eq!(pending.peer_addr(), "peer");
        assert_eq!(pool.used(), peer.len());
        drop(pending);
        assert_eq!(pool.used(), 0);
    }
    let first = b"abcd";
    let second = b"e";
    let maximum = MAX_PENDING_CLIENTHELLO
        .checked_add(MAX_CHANNEL_PAYLOAD)
        .unwrap();
    let old = bounded_vec_capacity(first.len(), maximum).unwrap();
    let next = bounded_vec_capacity(first.len() + second.len(), maximum).unwrap();
    let pool = AllocationPoolV1::new(peer.len() + old + next).unwrap();
    let mut pending = PendingClientHello::admitted(peer, Some(Arc::clone(&pool))).unwrap();
    pending.append(first).unwrap();
    let blocker = pool.reserve_unpublished(1).unwrap();
    assert!(pending.append(second).is_err());
    assert_eq!(pending.buffered(), first);
    drop(blocker);
    pending.append(second).unwrap();
    assert_eq!(pending.buffered(), b"abcde");
    assert_eq!(pool.used(), peer.len() + next);
    drop(pending);
    assert_eq!(pool.used(), 0);
    let mut pending = PendingClientHello::new(&[0xff]).unwrap();
    assert_eq!(pending.peer_addr(), "<invalid>");
    pending.append(&vec![0; MAX_PENDING_CLIENTHELLO]).unwrap();
    assert_eq!(pending.buffered().len(), MAX_PENDING_CLIENTHELLO);
    pending.append(&[0]).unwrap();
    assert_eq!(pending.buffered().len(), MAX_PENDING_CLIENTHELLO + 1);
    assert!(pending.append(&[]).is_err());
    let mut pending = PendingClientHello::new(peer).unwrap();
    assert!(pending.append(&vec![0; MAX_CHANNEL_PAYLOAD + 1]).is_err());
    assert!(pending.buffered().is_empty());
    eprintln!("PENDING-CLIENT-PAID: peer/refusal/old-new backing/final-chunk policy PASS");
}
