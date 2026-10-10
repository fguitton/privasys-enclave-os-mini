// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Lock-free Single-Producer Single-Consumer (SPSC) ring buffer.
//!
//! Designed for shared-memory communication between SGX enclave and host:
//! - Allocated in **host memory** (untrusted)
//! - Enclave can read/write host memory directly (no OCALL needed)
//! - Host cannot read enclave memory
//!
//! Two queues per channel:
//! - `enc_to_host`: enclave writes (producer), host reads (consumer)
//! - `host_to_enc`: host writes (producer), enclave reads (consumer)
//!
//! # Memory layout
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │  SpscQueueHeader (cache-line aligned)            │
//! │  ┌──────────┬──────────┬──────────┬────────────┐ │
//! │  │ head: u64│ pad      │ tail: u64│ pad        │ │
//! │  │ (64B)    │          │ (64B)    │            │ │
//! │  └──────────┴──────────┴──────────┴────────────┘ │
//! │  capacity: u64                                   │
//! │  buffer: [u8; capacity]                          │
//! └──────────────────────────────────────────────────┘
//! ```
//!
//! # Message framing
//!
//! Each message in the ring is prefixed with a 4-byte little-endian length:
//! ```text
//! [4 bytes: msg_len (LE u32)] [msg_len bytes: payload]
//! ```
//!
//! # Safety
//!
//! The queue header lives in host memory. The enclave accesses it via raw
//! pointers. This is safe because SGX guarantees the enclave can read/write
//! untrusted memory, and the SPSC discipline ensures no data races when
//! used correctly (one producer, one consumer per queue direction).

#[cfg(feature = "sgx")]
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(feature = "sgx"))]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "sgx")]
use alloc::vec;
#[cfg(feature = "sgx")]
use alloc::vec::Vec;

/// Default ring buffer capacity: 2 MiB. Must be a power of 2.
pub const DEFAULT_QUEUE_CAPACITY: u64 = 2 * 1024 * 1024;

/// Cache line size for padding (avoid false sharing).
const CACHE_LINE: usize = 64;

/// Message header size (4 bytes for length prefix).
pub const MSG_HEADER_SIZE: usize = 4;

/// Shared channel allocation bounds, owned by the queue primitive.
pub const MIN_SHARED_QUEUE_CAPACITY: u64 = 4096;
pub const MAX_SHARED_QUEUE_CAPACITY: u64 = 16 * 1024 * 1024;
/// Existing maximum complete ring frame, including its length prefix.
pub const MAX_RING_FRAME_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum message payload; complete framing is checked against actual capacity.
pub const MAX_MSG_SIZE: u32 = (MAX_RING_FRAME_BYTES - MSG_HEADER_SIZE as u64) as u32;
const _: () = assert!(
    DEFAULT_QUEUE_CAPACITY.is_power_of_two()
        && DEFAULT_QUEUE_CAPACITY >= MIN_SHARED_QUEUE_CAPACITY
        && DEFAULT_QUEUE_CAPACITY <= MAX_SHARED_QUEUE_CAPACITY
        && MAX_RING_FRAME_BYTES <= MAX_SHARED_QUEUE_CAPACITY
        && MAX_RING_FRAME_BYTES > MSG_HEADER_SIZE as u64
        && MAX_RING_FRAME_BYTES <= u32::MAX as u64
);

pub const fn shared_queue_capacity_valid(capacity: u64) -> bool {
    capacity.is_power_of_two()
        && capacity >= MIN_SHARED_QUEUE_CAPACITY
        && capacity <= MAX_SHARED_QUEUE_CAPACITY
}

/// Complete frames must fit both the primitive ceiling and the actual ring.
pub const fn max_message_bytes(capacity: u64) -> usize {
    let frame = if capacity < MAX_RING_FRAME_BYTES { capacity } else { MAX_RING_FRAME_BYTES };
    frame.saturating_sub(MSG_HEADER_SIZE as u64) as usize
}

/// The shared queue header, laid out for cache-line alignment.
///
/// Producer owns `head`, consumer owns `tail`. Both in host memory.
/// - Producer reads `tail` (Acquire) to check space, writes `head` (Release) after write
/// - Consumer reads `head` (Acquire) to check data, writes `tail` (Release) after read
#[repr(C, align(128))]
pub struct SpscQueueHeader {
    /// Next write position (owned by producer, read by consumer).
    /// Padded to its own cache line.
    pub head: AtomicU64,
    _pad_head: [u8; CACHE_LINE - 8],

    /// Next read position (owned by consumer, read by producer).
    /// Padded to its own cache line.
    pub tail: AtomicU64,
    _pad_tail: [u8; CACHE_LINE - 8],

    /// Capacity of the ring buffer (power of 2, immutable after init).
    pub capacity: u64,

    /// Reserved for future use / alignment.
    _reserved: [u64; 7],
}

impl SpscQueueHeader {
    /// Create a new zeroed header with the given capacity.
    pub fn new(capacity: u64) -> Self {
        assert!(capacity.is_power_of_two(), "capacity must be power of 2");
        assert!(capacity >= MIN_SHARED_QUEUE_CAPACITY, "capacity must be >= 4096");
        assert!(shared_queue_capacity_valid(capacity), "invalid shared queue capacity");
        Self {
            head: AtomicU64::new(0),
            _pad_head: [0; CACHE_LINE - 8],
            tail: AtomicU64::new(0),
            _pad_tail: [0; CACHE_LINE - 8],
            capacity,
            _reserved: [0; 7],
        }
    }

    /// Mask a position to an index in the ring buffer.
    #[inline(always)]
    pub fn mask(&self, pos: u64) -> usize {
        (pos & (self.capacity - 1)) as usize
    }

    /// Available bytes for reading.
    #[inline]
    pub fn available_read(&self) -> u64 {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }

    /// Available space for writing.
    #[inline]
    pub fn available_write(&self) -> u64 {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        self.capacity - head.wrapping_sub(tail)
    }
}

// ---------------------------------------------------------------------------
//  Producer (writer) side
// ---------------------------------------------------------------------------

/// Producer handle – writes messages into the ring buffer.
///
/// # Safety
/// `buf_ptr` must point to a valid `[u8; capacity]` region in host memory
/// that remains valid for the lifetime of this handle.
pub struct SpscProducer {
    header: *const SpscQueueHeader,
    buf_ptr: *mut u8,
    /// Trusted capacity supplied by the caller that validated the backing range.
    /// Enclave callers use `from_raw_with_capacity` to avoid rereading a
    /// mutable untrusted header after validation.
    capacity: u64,
}

unsafe impl Send for SpscProducer {}
unsafe impl Sync for SpscProducer {}

impl SpscProducer {
    /// Create a producer from raw pointers to the shared header and buffer.
    ///
    /// # Safety
    /// - `header` must point to a valid, aligned `SpscQueueHeader`
    /// - `buf_ptr` must point to a `[u8; header.capacity]` buffer
    /// - Only one producer may exist for a given queue
    pub unsafe fn from_raw(header: *const SpscQueueHeader, buf_ptr: *mut u8) -> Self {
        let capacity = core::ptr::read_volatile(core::ptr::addr_of!((*header).capacity));
        Self::from_raw_with_capacity(header, buf_ptr, capacity)
    }

    /// Construct with an already validated capacity; never reread host geometry.
    ///
    /// # Safety
    /// The header must be valid and aligned, the buffer must cover `capacity`
    /// bytes for the handle lifetime, and only one endpoint of this role may
    /// exist. The caller validates the scalar and backing range together.
    pub unsafe fn from_raw_with_capacity(
        header: *const SpscQueueHeader, buf_ptr: *mut u8, capacity: u64,
    ) -> Self {
        assert!(shared_queue_capacity_valid(capacity), "invalid shared queue capacity");
        Self {
            header,
            buf_ptr,
            capacity,
        }
    }

    /// Read-only diagnostic positions; never completion or authority evidence.
    pub fn diagnostic_positions(&self)->(u64,u64) {
        let header=unsafe {&*self.header};
        (header.head.load(Ordering::Acquire),header.tail.load(Ordering::Acquire))
    }

    /// Maximum payload for this endpoint's trusted capacity snapshot.
    pub const fn max_message_bytes(&self) -> usize {
        max_message_bytes(self.capacity)
    }

    pub fn message_len_valid(&self, bytes: usize) -> bool {
        bytes <= self.max_message_bytes()
    }

    /// Try to write a message. Oversize and transient queue pressure both refuse.
    pub fn try_send(&self, msg: &[u8]) -> Result<(), ()> {
        if !self.message_len_valid(msg.len()) {
            return Err(());
        }
        let hdr = unsafe { &*self.header };
        let total = MSG_HEADER_SIZE as u64 + msg.len() as u64;

        // Check available space
        let head = hdr.head.load(Ordering::Relaxed);
        let tail = hdr.tail.load(Ordering::Acquire);
        let used = head.wrapping_sub(tail);
        if used > self.capacity {
            return Err(());
        }
        let free = self.capacity - used;

        if free < total {
            return Err(()); // Queue is full
        }

        // Write length header
        let len_bytes = (msg.len() as u32).to_le_bytes();
        self.write_bytes(head, &len_bytes);

        // Write payload
        self.write_bytes(head + MSG_HEADER_SIZE as u64, msg);

        // Publish: advance head with Release ordering
        hdr.head.store(head + total, Ordering::Release);
        Ok(())
    }

    /// Blocking send with permanent size refusal before waiting for space.
    pub fn send_bounded(&self, msg: &[u8]) -> Result<(), ()> {
        if !self.message_len_valid(msg.len()) {
            return Err(());
        }
        loop {
            match self.try_send(msg) {
                Ok(()) => return Ok(()),
                Err(()) => core::hint::spin_loop(),
            }
        }
    }

    /// Legacy convenience API; invalid geometry fails instead of spinning forever.
    pub fn send(&self, msg: &[u8]) {
        self.send_bounded(msg).expect("message exceeds actual queue capacity");
    }

    /// Write bytes into the ring buffer at the given offset, handling wrap-around.
    fn write_bytes(&self, offset: u64, data: &[u8]) {
        let cap = self.capacity as usize;
        let start = (offset & (self.capacity - 1)) as usize;
        let first = data.len().min(cap - start);
        // The producer's available-space check owns exactly these ring bytes.
        // Staging changes neither framing nor the Release publication boundary.
        unsafe {
            copy_to_shared(&data[..first], self.buf_ptr.add(start));
            if first < data.len() {
                copy_to_shared(&data[first..], self.buf_ptr);
            }
        }
    }
}

/// Copy an already bounded shared ring segment into trusted storage. The
/// linked SDK memcpy uses repeated small external reads when source and
/// destination alignment modulo eight differ. A fixed trusted staging buffer
/// matches the source alignment; every external read still uses SDK memcpy.
/// No padding or additional ring bytes are copied, and publication is unchanged.
///
/// Safety: `source` must be readable for exactly out.len() bytes and must not
/// overlap `out`. The caller retains its existing SPSC reservation and bounds.
unsafe fn copy_from_shared(source: *const u8, out: &mut [u8]) {
    #[cfg(any(feature = "sgx", target_vendor = "teaclave", test))]
    if out.len() >= 64 && ((source as usize ^ out.as_ptr() as usize) & 7) != 0 {
        #[repr(align(8))]
        struct Aligned([u8; 4096 + 8]);
        let mut staging = Aligned([0; 4096 + 8]);
        let prefix = source as usize & 7;
        for (index, chunk) in out.chunks_mut(4096).enumerate() {
            // Preserve the staging allocation and SDK call across optimization.
            let destination = core::hint::black_box(staging.0.as_mut_ptr().add(prefix));
            core::ptr::copy_nonoverlapping(source.add(index * 4096), destination, chunk.len());
            chunk.copy_from_slice(&staging.0[prefix..prefix + chunk.len()]);
        }
        return;
    }
    core::ptr::copy_nonoverlapping(source, out.as_mut_ptr(), out.len());
}

/// Copy into an exclusively reserved shared ring segment, without widening
/// its range. Intel SDK 2.30's memcpy_verw uses per-byte mitigation when source
/// and destination have different alignment modulo eight. Match that alignment
/// using a fixed trusted staging buffer; the SDK still handles every external
/// write, including all unaligned prefix/tail bytes. No mitigation is bypassed.
///
/// Safety: `destination` must be writable for exactly data.len() bytes and
/// must not overlap `data`. This is the same contract as copy_nonoverlapping.
unsafe fn copy_to_shared(data: &[u8], destination: *mut u8) {
    #[cfg(any(feature = "sgx", target_vendor = "teaclave", test))]
    if data.len() >= 64 && ((data.as_ptr() as usize ^ destination as usize) & 7) != 0 {
        // Chunks have a multiple-of-eight stride; the matching prefix remains
        // constant. Padding is never written to the ring or made part of a frame.
        #[repr(align(8))]
        struct Aligned([u8; 4096 + 8]);
        let mut staging = Aligned([0; 4096 + 8]);
        let prefix = destination as usize & 7;
        for (index, chunk) in data.chunks(4096).enumerate() {
            staging.0[prefix..prefix + chunk.len()].copy_from_slice(chunk);
            // Preserve the explicit staging allocation across optimization.
            // This is a compiler barrier only, not a memory-ordering substitute.
            let source = core::hint::black_box(staging.0.as_ptr().add(prefix));
            core::ptr::copy_nonoverlapping(source, destination.add(index * 4096), chunk.len());
        }
        return;
    }
    core::ptr::copy_nonoverlapping(data.as_ptr(), destination, data.len());
}

// ---------------------------------------------------------------------------
//  Consumer (reader) side
// ---------------------------------------------------------------------------

/// Consumer handle – reads messages from the ring buffer.
pub struct SpscConsumer {
    header: *const SpscQueueHeader,
    buf_ptr: *const u8,
    /// Trusted-at-construction capacity snapshot; see [`SpscProducer`].
    capacity: u64,
}

unsafe impl Send for SpscConsumer {}
unsafe impl Sync for SpscConsumer {}

impl SpscConsumer {
    /// Create a consumer from raw pointers.
    ///
    /// # Safety
    /// Same requirements as `SpscProducer::from_raw`.
    pub unsafe fn from_raw(header: *const SpscQueueHeader, buf_ptr: *const u8) -> Self {
        let capacity = core::ptr::read_volatile(core::ptr::addr_of!((*header).capacity));
        Self::from_raw_with_capacity(header, buf_ptr, capacity)
    }

    /// Construct with an already validated capacity; never reread host geometry.
    ///
    /// # Safety
    /// The header must be valid and aligned, the buffer must cover `capacity`
    /// bytes for the handle lifetime, and only one endpoint of this role may
    /// exist. The caller validates the scalar and backing range together.
    pub unsafe fn from_raw_with_capacity(
        header: *const SpscQueueHeader, buf_ptr: *const u8, capacity: u64,
    ) -> Self {
        assert!(shared_queue_capacity_valid(capacity), "invalid shared queue capacity");
        Self {
            header,
            buf_ptr,
            capacity,
        }
    }

    /// Try to read a message. Returns `Some(Vec<u8>)` or `None` if empty.
    pub fn try_recv(&self) -> Option<Vec<u8>> {
        let hdr = unsafe { &*self.header };

        let head = hdr.head.load(Ordering::Acquire);
        let tail = hdr.tail.load(Ordering::Relaxed);
        let avail = head.wrapping_sub(tail);

        if avail > self.capacity {
            return None;
        }
        if avail < MSG_HEADER_SIZE as u64 {
            return None; // Not enough data for a message header
        }

        // Read length header
        let mut len_bytes = [0u8; MSG_HEADER_SIZE];
        self.read_bytes(tail, &mut len_bytes);
        let msg_len = u32::from_le_bytes(len_bytes) as u64;

        if msg_len > max_message_bytes(self.capacity) as u64 {
            // Corrupted message – skip and advance tail past the header
            hdr.tail
                .store(tail + MSG_HEADER_SIZE as u64, Ordering::Release);
            return None;
        }

        let total = MSG_HEADER_SIZE as u64 + msg_len;
        if total > self.capacity || avail < total {
            return None; // Incomplete message (shouldn't happen with proper producer)
        }

        // Read payload
        let mut payload = vec![0u8; msg_len as usize];
        self.read_bytes(tail + MSG_HEADER_SIZE as u64, &mut payload);

        // Advance tail
        hdr.tail.store(tail + total, Ordering::Release);

        Some(payload)
    }

    /// Blocking receive: spins until a message is available.
    pub fn recv(&self) -> Vec<u8> {
        loop {
            if let Some(msg) = self.try_recv() {
                return msg;
            }
            core::hint::spin_loop();
        }
    }

    /// Read bytes from the ring buffer at the given offset, handling wrap-around.
    fn read_bytes(&self, offset: u64, out: &mut [u8]) {
        let cap = self.capacity as usize;
        let start = (offset & (self.capacity - 1)) as usize;
        let end = start + out.len();

        if end <= cap {
            unsafe {
                copy_from_shared(self.buf_ptr.add(start), out);
            }
        } else {
            let first_chunk = cap - start;
            unsafe {
                copy_from_shared(self.buf_ptr.add(start), &mut out[..first_chunk]);
                copy_from_shared(self.buf_ptr, &mut out[first_chunk..]);
            }
        }
    }

    /// Check if there's a message available without consuming it.
    pub fn is_empty(&self) -> bool {
        let hdr = unsafe { &*self.header };
        let head = hdr.head.load(Ordering::Acquire);
        let tail = hdr.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail) < MSG_HEADER_SIZE as u64
    }
}

// ---------------------------------------------------------------------------
//  Channel descriptor (passed via the single ECALL)
// ---------------------------------------------------------------------------

/// Pointers to a bidirectional shared-memory channel.
///
/// Allocated by the host; pointers passed to the enclave via a single ECALL.
/// All memory is in host (untrusted) address space.
#[repr(C)]
pub struct SharedChannelPtrs {
    /// Queue for enclave → host messages.
    pub enc_to_host_header: *mut SpscQueueHeader,
    pub enc_to_host_buffer: *mut u8,

    /// Queue for host → enclave messages.
    pub host_to_enc_header: *mut SpscQueueHeader,
    pub host_to_enc_buffer: *mut u8,

    /// Capacity of each ring buffer (both must be the same).
    pub capacity: u64,
}

unsafe impl Send for SharedChannelPtrs {}
unsafe impl Sync for SharedChannelPtrs {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: allocate a queue in normal heap memory for testing.
    fn alloc_test_queue(capacity: u64) -> (SpscProducer, SpscConsumer) {
        let header = Box::into_raw(Box::new(SpscQueueHeader::new(capacity)));
        let buffer = vec![0u8; capacity as usize];
        let buf_ptr = Box::into_raw(buffer.into_boxed_slice()) as *mut u8;
        unsafe {
            let producer = SpscProducer::from_raw(header, buf_ptr);
            let consumer = SpscConsumer::from_raw(header, buf_ptr);
            (producer, consumer)
        }
    }

    // ================================================================
    //  Basic operations
    // ================================================================

    #[test]
    fn test_single_message() {
        let (producer, consumer) = alloc_test_queue(4096);

        let msg = b"Hello, enclave!";
        assert_eq!(producer.diagnostic_positions(),(0,0));
        producer.try_send(msg).unwrap();
        let end=u64::try_from(msg.len()+MSG_HEADER_SIZE).unwrap();
        assert_eq!(producer.diagnostic_positions(),(end,0));
        let received = consumer.try_recv().unwrap();
        assert_eq!(received, msg);
        assert_eq!(producer.diagnostic_positions(),(end,end));
        assert!(consumer.try_recv().is_none(),"diagnostic snapshots never consume data");
    }

    #[test]
    fn test_empty_recv_returns_none() {
        let (_producer, consumer) = alloc_test_queue(4096);
        assert!(consumer.try_recv().is_none());
        assert!(consumer.is_empty());
    }

    #[test]
    fn capacity_is_snapshotted_before_untrusted_header_mutation() {
        let header = Box::into_raw(Box::new(SpscQueueHeader::new(4096)));
        let buffer = vec![0u8; 4096];
        let buf_ptr = Box::into_raw(buffer.into_boxed_slice()) as *mut u8;
        let (producer, consumer) = unsafe {
            (
                SpscProducer::from_raw(header, buf_ptr),
                SpscConsumer::from_raw(header, buf_ptr),
            )
        };

        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*header).capacity), 1 << 30);
        }
        producer.try_send(b"bounded").unwrap();
        assert_eq!(consumer.try_recv().unwrap(), b"bounded");
        // The validated scalar remains authoritative even when the untrusted
        // header changes before handle construction, as at the ECALL boundary.
        drop(producer);
        drop(consumer);
        let (producer, consumer) = unsafe {
            (SpscProducer::from_raw_with_capacity(header, buf_ptr, 4096),
             SpscConsumer::from_raw_with_capacity(header, buf_ptr, 4096))
        };
        assert_eq!(producer.max_message_bytes(), 4096 - MSG_HEADER_SIZE);
        let exact = vec![37; producer.max_message_bytes()];
        producer.send_bounded(&exact).unwrap();
        assert_eq!(consumer.try_recv().unwrap(), exact);
        assert!(producer.send_bounded(&vec![0; producer.max_message_bytes()+1]).is_err());
    }

    #[test]
    fn test_multiple_messages() {
        let (producer, consumer) = alloc_test_queue(4096);

        for i in 0u32..10 {
            let msg = i.to_le_bytes();
            producer.try_send(&msg).unwrap();
        }

        for i in 0u32..10 {
            let received = consumer.try_recv().unwrap();
            assert_eq!(received, i.to_le_bytes());
        }
    }

    #[test]
    fn test_wrap_around() {
        // Small capacity to force wrapping
        let (producer, consumer) = alloc_test_queue(4096);

        // Fill and drain multiple times to force wrap-around
        for round in 0..10 {
            let msg = vec![round as u8; 500]; // 500 bytes + 4 header = 504 per msg
                                              // Write ~7 messages to nearly fill 4096
            for _ in 0..7 {
                producer.try_send(&msg).unwrap();
            }
            for _ in 0..7 {
                let received = consumer.try_recv().unwrap();
                assert_eq!(received, msg);
            }
        }
    }

    #[test]
    fn test_full_queue_returns_err() {
        let (producer, consumer) = alloc_test_queue(4096);

        // Fill the queue
        let msg = vec![0xAA; 1000];
        let mut count = 0;
        while producer.try_send(&msg).is_ok() {
            count += 1;
            if count > 100 {
                panic!("should have filled by now");
            }
        }
        assert!(count > 0);

        // Drain one, should be able to write again
        let _ = consumer.try_recv().unwrap();
        producer.try_send(&msg).unwrap();
    }

    #[test]
    fn test_concurrent_producer_consumer() {
        let (producer, consumer) = alloc_test_queue(1 << 20); // 1 MiB

        let num_messages = 10_000;

        let producer_handle = std::thread::spawn(move || {
            for i in 0u64..num_messages {
                let msg = i.to_le_bytes();
                producer.send(&msg);
            }
        });

        let consumer_handle = std::thread::spawn(move || {
            for i in 0u64..num_messages {
                let msg = consumer.recv();
                assert_eq!(msg, i.to_le_bytes());
            }
        });

        producer_handle.join().unwrap();
        consumer_handle.join().unwrap();
    }

    // ================================================================
    //  Extended / edge-case tests
    // ================================================================

    #[test]
    fn test_zero_length_message() {
        let (producer, consumer) = alloc_test_queue(4096);
        producer.try_send(b"").unwrap();
        let received = consumer.try_recv().unwrap();
        assert!(received.is_empty());
    }

    #[test]
    fn test_one_byte_message() {
        let (producer, consumer) = alloc_test_queue(4096);
        producer.try_send(&[0x42]).unwrap();
        let received = consumer.try_recv().unwrap();
        assert_eq!(received, vec![0x42]);
    }

    #[test]
    fn test_exact_capacity_fill_drain() {
        // Capacity 4096, msg_header = 4 bytes per message.
        // A 1020-byte payload uses 1024 bytes total.  4096 / 1024 = exactly 4.
        let (producer, consumer) = alloc_test_queue(4096);
        let msg = vec![0xBB; 1020];
        for _ in 0..4 {
            producer.try_send(&msg).unwrap();
        }
        // Queue should be exactly full now
        assert!(producer.try_send(&[0]).is_err());

        for _ in 0..4 {
            let received = consumer.try_recv().unwrap();
            assert_eq!(received, msg);
        }
        assert!(consumer.is_empty());
    }

    #[test]
    fn test_message_too_large_rejected() {
        let (producer, _consumer) = alloc_test_queue(4096);
        // A message beyond the primitive payload ceiling is rejected
        let huge = vec![0u8; MAX_MSG_SIZE as usize + 1];
        assert!(producer.try_send(&huge).is_err());
    }

    #[test]
    fn test_message_larger_than_capacity_rejected() {
        let (producer, consumer) = alloc_test_queue(4096);
        let fits = vec![19u8; producer.max_message_bytes()];
        producer.send_bounded(&fits).unwrap();
        assert_eq!(consumer.try_recv().unwrap(), fits);
        let too_large = vec![23u8; producer.max_message_bytes() + 1];
        let positions = producer.diagnostic_positions();
        assert!(producer.send_bounded(&too_large).is_err());
        assert_eq!(producer.diagnostic_positions(), positions);
        assert!(consumer.try_recv().is_none());
        let (producer, consumer) = alloc_test_queue(DEFAULT_QUEUE_CAPACITY);
        let original_gap = vec![29u8; DEFAULT_QUEUE_CAPACITY as usize];
        assert!(original_gap.len() <= MAX_MSG_SIZE as usize);
        assert!(producer.send_bounded(&original_gap).is_err());
        let exact = vec![31u8; producer.max_message_bytes()];
        producer.send_bounded(&exact).unwrap();
        assert_eq!(consumer.try_recv().unwrap(), exact);
    }

    #[test]
    fn test_interleaved_send_recv() {
        let (producer, consumer) = alloc_test_queue(4096);
        for i in 0u32..100 {
            let msg = i.to_le_bytes();
            producer.try_send(&msg).unwrap();
            let received = consumer.try_recv().unwrap();
            assert_eq!(received, msg);
        }
    }

    #[test]
    fn test_is_empty_transitions() {
        let (producer, consumer) = alloc_test_queue(4096);
        assert!(consumer.is_empty());
        producer.try_send(b"data").unwrap();
        assert!(!consumer.is_empty());
        let _ = consumer.try_recv().unwrap();
        assert!(consumer.is_empty());
    }

    #[test]
    fn test_header_alignment() {
        let hdr = SpscQueueHeader::new(4096);
        let ptr = &hdr as *const SpscQueueHeader as usize;
        // Must be 128-byte aligned (repr(C, align(128)))
        assert_eq!(ptr % 128, 0);
    }

    #[test]
    #[should_panic(expected = "capacity must be power of 2")]
    fn test_non_power_of_two_capacity_panics() {
        SpscQueueHeader::new(5000);
    }

    #[test]
    #[should_panic(expected = "capacity must be >= 4096")]
    fn test_too_small_capacity_panics() {
        SpscQueueHeader::new(2048);
    }

    #[test]
    fn test_available_space_tracking() {
        let hdr = SpscQueueHeader::new(4096);
        assert_eq!(hdr.available_read(), 0);
        assert_eq!(hdr.available_write(), 4096);
    }

    #[test]
    fn test_concurrent_high_throughput() {
        // Larger test: 100k messages across threads
        let (producer, consumer) = alloc_test_queue(1 << 20);
        let num_messages: u64 = 100_000;

        let p = std::thread::spawn(move || {
            for i in 0..num_messages {
                let mut msg = Vec::with_capacity(16);
                msg.extend_from_slice(&i.to_le_bytes());
                msg.extend_from_slice(&(i.wrapping_mul(0xDEAD)).to_le_bytes());
                producer.send(&msg);
            }
        });

        let c = std::thread::spawn(move || {
            for i in 0..num_messages {
                let msg = consumer.recv();
                assert_eq!(msg.len(), 16);
                let val = u64::from_le_bytes(msg[0..8].try_into().unwrap());
                let check = u64::from_le_bytes(msg[8..16].try_into().unwrap());
                assert_eq!(val, i);
                assert_eq!(check, i.wrapping_mul(0xDEAD));
            }
        });

        p.join().unwrap();
        c.join().unwrap();
    }

    #[test]
    fn test_wrap_around_boundary_exact() {
        // Force a message to span the exact wrap boundary
        let cap: u64 = 4096;
        let (producer, consumer) = alloc_test_queue(cap);

        // Write a message that leaves exactly X bytes before the boundary,
        // then write a message that straddles it.
        // First fill up to near the end:
        let fill_msg = vec![0xAA; 2000]; // 2000 + 4 = 2004
        producer.try_send(&fill_msg).unwrap();
        let _ = consumer.try_recv().unwrap(); // drain; head = 2004, tail = 2004

        // Now write a message of ~3000 bytes that wraps around
        let wrap_msg: Vec<u8> = (0..3000u16).map(|i| (i & 0xFF) as u8).collect();
        producer.try_send(&wrap_msg).unwrap();
        let received = consumer.try_recv().unwrap();
        assert_eq!(received, wrap_msg);
    }

    #[test]
    fn test_variable_size_messages() {
        // All alignment pairs, staging boundaries and short tails retain the
        // exact source bytes and leave both destination guard regions intact.
        for source_offset in 0..8 {
            let source: Vec<u8> = (0..8208).map(|i| (i * 31) as u8).collect();
            for destination_offset in 0..8 {
                for length in [0, 1, 7, 8, 63, 64, 4095, 4096, 4097, 8193] {
                    let data = &source[source_offset..source_offset + length];
                    let mut destination = vec![0xa5; length + 24];
                    let start = 8 + destination_offset;
                    unsafe { copy_to_shared(data, destination.as_mut_ptr().add(start)) };
                    assert!(destination[..start].iter().all(|byte| *byte == 0xa5));
                    assert_eq!(&destination[start..start + length], data);
                    assert!(destination[start + length..]
                        .iter()
                        .all(|byte| *byte == 0xa5));
                    destination.fill(0xa5);
                    unsafe {
                        copy_from_shared(data.as_ptr(), &mut destination[start..start + length]);
                    }
                    assert!(destination[..start].iter().all(|byte| *byte == 0xa5));
                    assert_eq!(&destination[start..start + length], data);
                    assert!(destination[start + length..]
                        .iter()
                        .all(|byte| *byte == 0xa5));
                }
            }
        }

        let (producer, consumer) = alloc_test_queue(1 << 16); // 64 KiB
        let sizes = [
            0, 1, 7, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 500, 1000, 4000,
        ];
        for &size in &sizes {
            let msg: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            producer.try_send(&msg).unwrap();
        }
        for &size in &sizes {
            let expected: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let received = consumer.try_recv().unwrap();
            assert_eq!(received.len(), size);
            assert_eq!(received, expected);
        }
    }

    #[test]
    fn test_bidirectional_channel() {
        // Simulate the full host↔enclave channel with two queues
        let (enc_tx, host_rx) = alloc_test_queue(8192);
        let (host_tx, enc_rx) = alloc_test_queue(8192);

        let enclave = std::thread::spawn(move || {
            // Send a request
            enc_tx.send(b"PING");
            // Wait for response
            let resp = enc_rx.recv();
            assert_eq!(resp, b"PONG");
        });

        let host = std::thread::spawn(move || {
            // Read request
            let req = host_rx.recv();
            assert_eq!(req, b"PING");
            // Send response
            host_tx.send(b"PONG");
        });

        enclave.join().unwrap();
        host.join().unwrap();
    }
}
