//! Resource oracle for the current live ClientHello decoder, not a second codec.
use enclave_os_common::allocation::AllocationPoolV1;
#[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
use enclave_os_common::allocation::LoanAllocator;
#[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
use enclave_os_common::allocation::PoolMapAllocator;
#[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
type Backend = PoolMapAllocator;
#[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
type Backend = std::alloc::OwnedAllocator;
use rustls::internal::msgs::handshake::RetainedClientHello;
use std::alloc::{AllocError, Allocator, Layout};
use std::cell::RefCell;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::Arc;

// Fixed observer storage is outside the product pool and never grows in a
// measured scope. This is an instrumentation bound, not a TLS input limit.
const OBSERVED_REQUESTS: usize = 256;
struct Observation {
    requests: usize,
    refuse: Option<usize>,
    live: [Option<(usize, Layout)>; OBSERVED_REQUESTS],
}
#[derive(Clone)]
pub(super) struct Original {
    allocator: Backend,
    observation: Rc<RefCell<Observation>>,
}
impl Original {
    pub(super) fn new(pool: &Arc<AllocationPoolV1>) -> Self {
        #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
        let allocator = PoolMapAllocator::try_new(pool).unwrap();
        #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
        let allocator = LoanAllocator::from_pool_unpublished(pool)
            .unwrap()
            .owned_allocator();
        Self {
            allocator,
            observation: Rc::new(RefCell::new(Observation {
                requests: 0,
                refuse: None,
                live: [None; OBSERVED_REQUESTS],
            })),
        }
    }
    pub(super) fn requests(&self) -> usize {
        self.observation.borrow().requests
    }
    pub(super) fn arm(&self, refusal: Option<usize>) {
        let mut observed = self.observation.borrow_mut();
        observed.requests = 0;
        observed.refuse = refusal;
    }
    pub(super) fn backend_bytes(&self) -> usize {
        self.observation
            .borrow()
            .live
            .iter()
            .flatten()
            .map(|(_, layout)| backend_bytes(*layout))
            .sum()
    }
}
// SAFETY: delegates exact pointer/layout ownership to the original pool
// allocator. Refusal occurs before delegation, and observation never allocates.
unsafe impl Allocator for Original {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let mut observed = self.observation.borrow_mut();
        let request = observed.requests;
        observed.requests += 1;
        if observed.refuse == Some(request) {
            return Err(AllocError);
        }
        let block = self.allocator.allocate(layout)?;
        if layout.size() != 0 {
            let slot = observed
                .live
                .iter_mut()
                .find(|slot| slot.is_none())
                .unwrap();
            *slot = Some((block.cast::<u8>().as_ptr() as usize, layout));
        }
        Ok(block)
    }
    unsafe fn deallocate(&self, pointer: NonNull<u8>, layout: Layout) {
        if layout.size() != 0 {
            let mut observed = self.observation.borrow_mut();
            let slot = observed
                .live
                .iter_mut()
                .find(|slot| **slot == Some((pointer.as_ptr() as usize, layout)))
                .unwrap();
            *slot = None;
        }
        // SAFETY: the pointer/layout pair above is the original live request.
        unsafe {
            self.allocator.deallocate(pointer, layout);
        }
    }
}
fn backend_bytes(layout: Layout) -> usize {
    #[cfg(not(any(target_env = "sgx", target_vendor = "teaclave")))]
    {
        PoolMapAllocator::backend_layout(layout).unwrap().size()
    }
    #[cfg(any(target_env = "sgx", target_vendor = "teaclave"))]
    {
        LoanAllocator::required_backend_bytes(layout).unwrap()
    }
}
pub(super) fn without_global<T>(action: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    {
        crate::ratls::session::retained_tls_config::check_no_global_children(action)
    }
    #[cfg(not(test))]
    {
        action()
    }
}

fn decode(
    bytes: &[u8],
    origin: &Original,
) -> Result<RetainedClientHello<Original>, rustls::InvalidMessage> {
    without_global(|| RetainedClientHello::read_bytes_in(bytes, origin.clone()))
}
fn encoded(value: &RetainedClientHello<Original>) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.encode_to(&mut bytes);
    bytes
}
fn check_decode_refusals(
    bytes: &[u8],
    origin: &Original,
    pool: &Arc<AllocationPoolV1>,
    metadata: usize,
    requests: usize,
) {
    for refusal in 0..requests {
        origin.arm(Some(refusal));
        let result = decode(bytes, origin);
        assert!(matches!(
            result,
            Err(rustls::InvalidMessage::AllocationFailed)
        ));
        assert_eq!(origin.backend_bytes(), 0);
        assert_eq!(pool.used(), metadata);
    }
    origin.arm(None);
}
fn check_clone_refusals(
    value: &RetainedClientHello<Original>,
    origin: &Original,
    pool: &Arc<AllocationPoolV1>,
    metadata: usize,
) {
    let original = encoded(value);
    let original_bytes = origin.backend_bytes();
    origin.arm(None);
    let copy = without_global(|| value.try_clone_in(origin.clone())).unwrap();
    let requests = origin.observation.borrow().requests;
    assert_eq!(encoded(&copy), original);
    assert_eq!(pool.used(), metadata + origin.backend_bytes());
    drop(copy);
    assert_eq!(origin.backend_bytes(), original_bytes);
    for refusal in 0..requests {
        origin.arm(Some(refusal));
        assert!(without_global(|| value.try_clone_in(origin.clone())).is_err());
        assert_eq!(origin.backend_bytes(), original_bytes);
        assert_eq!(pool.used(), metadata + original_bytes);
        assert_eq!(encoded(value), original);
    }
    origin.arm(None);
}
fn check_malformed(origin: &Original, pool: &Arc<AllocationPoolV1>, metadata: usize) {
    let mut trailing = hello(&[]);
    trailing.push(0);
    let duplicate = hello(&[(0x7777, vec![1]), (0x7777, vec![2])]);
    let after_psk = hello(&[(41, psk()), (0x7777, vec![])]);
    for (bytes, expected) in [
        (
            trailing,
            rustls::InvalidMessage::TrailingData("ClientHelloPayload"),
        ),
        (
            duplicate,
            rustls::InvalidMessage::DuplicateExtension(0x7777),
        ),
        (
            after_psk,
            rustls::InvalidMessage::PreSharedKeyIsNotFinalExtension,
        ),
        (
            hello(&[(0xffff, vec![]), (0xffff, vec![])]),
            rustls::InvalidMessage::DuplicateExtension(0xffff),
        ),
    ] {
        assert_eq!(decode(&bytes, origin).err(), Some(expected));
        assert_eq!(origin.backend_bytes(), 0);
        assert_eq!(pool.used(), metadata);
    }
}
#[cfg(test)]
pub(super) fn check() {
    let pool = AllocationPoolV1::new(1024 * 1024).unwrap();
    check_in(&pool);
    assert_eq!(pool.used(), 0);
}
pub(super) fn check_in(pool: &Arc<AllocationPoolV1>) {
    let before = pool.used();
    let bytes = rich_hello();
    let origin = Original::new(pool);
    let metadata = pool.used();
    let alias = origin.clone();
    assert_eq!(pool.used(), metadata);
    let value = decode(&bytes, &origin).unwrap();
    let requests = origin.observation.borrow().requests;
    assert!(requests > 0);
    assert_eq!(pool.used(), metadata + origin.backend_bytes());
    check_wire(&value);
    check_clone_refusals(&value, &origin, pool, metadata);
    drop(value);
    assert_eq!(pool.used(), metadata);
    check_decode_refusals(&bytes, &origin, pool, metadata, requests);
    check_malformed(&origin, pool, metadata);
    check_alternative_fields(&origin, pool, metadata);
    drop(origin);
    assert_eq!(pool.used(), metadata);
    drop(alias);
    assert_eq!(pool.used(), before);
}
fn u16_list(bytes: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}
fn psk() -> Vec<u8> {
    let mut out = u16_list(&[0, 3, 1, 2, 3, 0, 0, 0, 7]);
    out.extend_from_slice(&u16_list(&[3, 4, 5, 6]));
    out
}
fn hello(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![3, 3];
    out.extend_from_slice(&[7; 32]);
    out.push(0); // empty SessionId
    out.extend_from_slice(&[0, 2, 0x13, 1, 1, 0]);
    let mut body = Vec::new();
    for (typ, bytes) in extensions {
        body.extend_from_slice(&typ.to_be_bytes());
        body.extend_from_slice(&u16_list(bytes));
    }
    out.extend_from_slice(&u16_list(&body));
    out
}
fn rich_hello() -> Vec<u8> {
    hello(&rich_extensions())
}
fn rich_extensions() -> Vec<(u16, Vec<u8>)> {
    let name = b"a.test";
    let mut sni = vec![0];
    sni.extend_from_slice(&u16_list(name));
    let mut ocsp = vec![1];
    ocsp.extend_from_slice(&u16_list(&u16_list(&[1, 2])));
    ocsp.extend_from_slice(&u16_list(&[3, 4]));
    let mut ech = vec![0, 0, 1, 0, 1, 7];
    ech.extend_from_slice(&u16_list(&[8, 9]));
    ech.extend_from_slice(&u16_list(&[10, 11]));
    vec![
        (0, u16_list(&sni)),
        (5, ocsp),
        (10, u16_list(&[0, 29, 0, 23])),
        (11, vec![1, 0]),
        (13, u16_list(&[4, 3, 8, 4])),
        (16, u16_list(&[2, b'h', b'2', 3, b'f', b'o', b'o'])),
        (19, vec![1, 0]),
        (20, vec![1, 0]),
        (23, vec![]),
        (27, vec![2, 0, 1]),
        (35, vec![1, 2]),
        (42, vec![]),
        (43, vec![2, 3, 4]),
        (44, u16_list(&[3, 4])),
        (45, vec![1, 1]),
        (47, u16_list(&u16_list(&[5, 6]))),
        (51, u16_list(&[0, 29, 0, 3, 1, 2, 3])),
        (57, vec![1, 2]),
        (58, vec![1, 1]),
        (0xff01, vec![1, 7]),
        (0xffa5, vec![3, 4]),
        (0xfd00, vec![2, 0, 10]),
        (0xfe0d, ech),
        (41, psk()),
    ]
}

fn check_wire(value: &RetainedClientHello<Original>) {
    // Independent known order derived before the new decoder from the saved
    // rustls low_quality_integer_hash(seed=0) and special ECH/PSK-last rule.
    // Fixed pins deliberately do not recompute that algorithm from live code.
    const ORDER: [u16; 24] = [
        5, 19, 44, 16, 65281, 57, 43, 11, 27, 10, 20, 0, 47, 65445, 13, 58, 35, 23, 42, 51, 45,
        64768, 65037, 41,
    ];
    let extensions = rich_extensions();
    let mut ordered: Vec<_> = ORDER
        .iter()
        .map(|typ| {
            extensions
                .iter()
                .find(|(present, _)| present == typ)
                .unwrap()
                .clone()
        })
        .collect();
    assert_eq!(encoded(value), hello(&ordered));
    ordered.retain(|(typ, _)| ![10, 13].contains(typ));
    ordered
        .iter_mut()
        .find(|(typ, _)| *typ == 0xfd00)
        .unwrap()
        .1 = vec![4, 0, 10, 0, 13];
    let mut compressed = Vec::new();
    value.encode_inner_to(&[10, 13], &mut compressed);
    assert_eq!(compressed, hello(&ordered));
}

fn check_alternative_fields(origin: &Original, pool: &Arc<AllocationPoolV1>, metadata: usize) {
    let mut cases = vec![
        hello(&[]),
        hello(&[(5, vec![9, 1, 2, 3])]),
        hello(&[(0xfe0d, vec![1])]),
    ];
    let mut absent_extensions = hello(&[]);
    absent_extensions.truncate(absent_extensions.len() - 2);
    cases.push(absent_extensions);
    for name in [b"127.0.0.1".as_slice(), b"bad\0name"] {
        let mut value = vec![0];
        value.extend_from_slice(&u16_list(name));
        cases.push(hello(&[(0, u16_list(&value))]));
    }
    cases.push(hello(&[(0, u16_list(&[1, 7, 8, 9]))]));
    for bytes in cases {
        origin.arm(None);
        let value = decode(&bytes, origin).unwrap();
        let requests = origin.observation.borrow().requests;
        assert_eq!(pool.used(), metadata + origin.backend_bytes());
        check_clone_refusals(&value, origin, pool, metadata);
        drop(value);
        assert_eq!(pool.used(), metadata);
        check_decode_refusals(&bytes, origin, pool, metadata, requests);
    }
}
