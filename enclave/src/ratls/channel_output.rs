//! Inbound server channel bytes and queue backing keep independent physical credit.
use enclave_os_common::{
    allocation::{bounded_vec_capacity, AllocationLeaseV1, AllocationPoolV1},
    channel,
};
use std::{collections::VecDeque, sync::Arc};
/// Existing server backlog policy, in complete channel-message bytes.
pub(crate) const MAX_PENDING_ENCLAVE_OUTPUT: usize = 4 * 1024 * 1024;
pub(crate) struct Message {
    bytes: Vec<u8>,
    _allocation: Option<AllocationLeaseV1>,
}
impl core::ops::Deref for Message {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Message {
    pub(crate) fn encode(
        pool: Option<&Arc<AllocationPoolV1>>,
        payload: usize,
        encode: impl FnOnce() -> Vec<u8>,
    ) -> Result<Self, &'static str> {
        if payload > channel::MAX_CHANNEL_PAYLOAD {
            return Err("channel payload exceeds codec");
        }
        let length = channel::channel_message_length(payload).ok_or("channel length overflow")?;
        let allocation = match pool {
            Some(pool) => Some(
                pool.reserve_unpublished(length)
                    .ok_or("channel admission exhausted")?,
            ),
            None => None,
        };
        let bytes = encode();
        if bytes.len() != length || bytes.capacity() != length {
            return Err("channel encoder geometry changed");
        }
        if let Some(credit) = &allocation {
            credit.activate_release_notification();
        }
        Ok(Self {
            bytes,
            _allocation: allocation,
        })
    }
}
#[derive(Default)]
pub(crate) struct Queue {
    messages: VecDeque<Message>,
    allocation: Option<AllocationLeaseV1>,
    bytes: usize,
}
impl Queue {
    fn slot_bytes(count: usize) -> Option<usize> {
        core::alloc::Layout::array::<Message>(count)
            .ok()
            .map(|layout| layout.size())
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
    pub(crate) fn front(&self) -> Option<&Message> {
        self.messages.front()
    }
    pub(crate) fn pop_front(&mut self) -> Option<Message> {
        let message = self.messages.pop_front()?;
        self.bytes -= message.len();
        Some(message)
    }
    pub(crate) fn push(
        &mut self,
        message: Message,
        pool: Option<&Arc<AllocationPoolV1>>,
    ) -> Result<(), &'static str> {
        let bytes = self
            .bytes
            .checked_add(message.len())
            .filter(|n| *n <= MAX_PENDING_ENCLAVE_OUTPUT)
            .ok_or("channel backlog exceeds cap")?;
        let required = self
            .messages
            .len()
            .checked_add(1)
            .ok_or("channel slot overflow")?;
        if required > self.messages.capacity() {
            // Each encoded message contains its header even for an empty close.
            let maximum = MAX_PENDING_ENCLAVE_OUTPUT / channel::CHANNEL_MSG_HEADER;
            let capacity =
                bounded_vec_capacity(required, maximum).ok_or("channel slot geometry overflow")?;
            let backing = Self::slot_bytes(capacity).ok_or("channel slot layout overflow")?;
            let allocation = match pool {
                Some(pool) => Some(
                    pool.reserve_unpublished(backing)
                        .ok_or("channel slot admission exhausted")?,
                ),
                None => None,
            };
            let mut messages = VecDeque::new();
            messages
                .try_reserve_exact(capacity)
                .map_err(|_| "channel slot allocation failed")?;
            if messages.capacity() != capacity {
                return Err("channel slot capacity changed");
            }
            messages.extend(self.messages.drain(..));
            drop(core::mem::replace(&mut self.messages, messages));
            drop(core::mem::replace(&mut self.allocation, allocation));
            if let Some(credit) = &self.allocation {
                credit.activate_release_notification();
            }
        }
        self.messages.push_back(message);
        self.bytes = bytes;
        Ok(())
    }
}
#[cfg(test)]
pub(super) fn check() {
    let length = channel::channel_message_length(1).unwrap();
    let small = AllocationPoolV1::new(length - 1).unwrap();
    let invoked = std::cell::Cell::new(false);
    assert!(Message::encode(Some(&small), 1, || {
        invoked.set(true);
        channel::encode_tcp_data(7, &[9])
    })
    .is_err());
    assert!(!invoked.get());
    assert_eq!(small.used(), 0);
    let slot = Queue::slot_bytes(1).unwrap();
    let pool = AllocationPoolV1::new(length * 2 + slot * 3).unwrap();
    let mut queue = Queue::default();
    queue
        .push(
            Message::encode(Some(&pool), 1, || channel::encode_tcp_data(7, &[9])).unwrap(),
            Some(&pool),
        )
        .unwrap();
    assert_eq!(pool.used(), length + slot);
    let blocker = pool.reserve(1).unwrap();
    assert!(queue
        .push(
            Message::encode(Some(&pool), 1, || channel::encode_tcp_data(8, &[10])).unwrap(),
            Some(&pool)
        )
        .is_err());
    assert_eq!(
        &queue.front().unwrap()[..],
        channel::encode_tcp_data(7, &[9])
    );
    assert_eq!(pool.used(), length + slot + 1);
    drop(blocker);
    queue
        .push(
            Message::encode(Some(&pool), 1, || channel::encode_tcp_data(8, &[10])).unwrap(),
            Some(&pool),
        )
        .unwrap();
    assert_eq!(pool.used(), length * 2 + slot * 2);
    let first = queue.pop_front().unwrap();
    let second = queue.pop_front().unwrap();
    assert_eq!(&first[..], channel::encode_tcp_data(7, &[9]));
    assert_eq!(&second[..], channel::encode_tcp_data(8, &[10]));
    assert!(queue.is_empty());
    drop(first);
    drop(second);
    assert_eq!(pool.used(), slot * 2);
    drop(queue);
    assert_eq!(pool.used(), 0);
    assert!(
        Message::encode(Some(&pool), channel::MAX_CHANNEL_PAYLOAD + 1, || panic!(
            "must refuse before encoder"
        ))
        .is_err()
    );
    assert!(Queue::slot_bytes(usize::MAX).is_none());
    let pool =
        AllocationPoolV1::new(MAX_PENDING_ENCLAVE_OUTPUT + Queue::slot_bytes(8).unwrap()).unwrap();
    let mut queue = Queue::default();
    let mut remaining = MAX_PENDING_ENCLAVE_OUTPUT;
    while remaining > 0 {
        let payload = (remaining - channel::CHANNEL_MSG_HEADER).min(channel::MAX_CHANNEL_PAYLOAD);
        let body = vec![13; payload];
        queue
            .push(
                Message::encode(Some(&pool), payload, || channel::encode_tcp_data(7, &body))
                    .unwrap(),
                Some(&pool),
            )
            .unwrap();
        remaining -= channel::channel_message_length(payload).unwrap();
    }
    assert_eq!(queue.bytes, MAX_PENDING_ENCLAVE_OUTPUT);
    assert!(queue
        .push(
            Message::encode(Some(&pool), 0, || channel::encode_tcp_close(7)).unwrap(),
            Some(&pool)
        )
        .is_err());
    assert_eq!(queue.bytes, MAX_PENDING_ENCLAVE_OUTPUT);
    drop(queue);
    assert_eq!(pool.used(), 0);
    eprintln!(
        "INBOUND-CHANNEL-PAID: original codec/old-new slots/FIFO/empty/4MiB/refusal/refund PASS"
    );
}
