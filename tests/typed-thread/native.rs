//! Actual SDK Native/task/capability source under explicit native host/TCS shims.
//! These prove ownership/failure mechanics; actual SGX execution remains the
//! signed five-case owner. No synthetic source/signing/consensus authority.
#![feature(allocator_api)]
extern crate alloc;
extern crate self as sgx_types;
#[path = "sdk/sgx_types/src/memory.rs"]
pub mod memory;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SgxStatus {
    Success,
    InvalidParameter,
    OutOfMemory,
    Unexpected,
    OutOfTcs,
    InvalidState,
}
pub mod error {
    pub use crate::SgxStatus;
    pub type SgxResult<T = ()> = Result<T, SgxStatus>;
    pub fn abort() -> ! {
        panic!("SDK abort")
    }
}
macro_rules! bail {
    ($e:expr) => {
        return Err($e)
    };
}
pub mod enclave {
    pub static UNINIT_FLAG: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    pub fn is_within_enclave(_: *const u8, _: usize) -> bool {
        true
    }
    pub trait EnclaveRange {
        fn is_host_range(&self) -> bool;
    }
    impl EnclaveRange for usize {
        fn is_host_range(&self) -> bool {
            true
        }
    }
}
pub mod sync {
    use std::ops::{Deref, DerefMut};
    use std::sync::{Mutex, MutexGuard};
    pub struct SpinMutex<T>(Mutex<T>);
    pub struct Guard<'a, T>(MutexGuard<'a, T>);
    std::thread_local! {pub static HELD:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};}
    impl<T> SpinMutex<T> {
        pub const fn new(v: T) -> Self {
            Self(Mutex::new(v))
        }
        pub fn lock(&self) -> Guard<'_, T> {
            let g = self.0.lock().unwrap();
            HELD.with(|n| n.set(n.get() + 1));
            Guard(g)
        }
    }
    impl<T> Deref for Guard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            &self.0
        }
    }
    impl<T> DerefMut for Guard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            &mut self.0
        }
    }
    impl<T> Drop for Guard<'_, T> {
        fn drop(&mut self) {
            HELD.with(|n| n.set(n.get() - 1));
        }
    }
}
pub mod tcs {
    pub mod tc {
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct TcsId(pub usize);
        impl TcsId {
            pub fn as_usize(self) -> usize {
                self.0
            }
        }
        pub struct TdFlags(pub u32);
        impl TdFlags {
            pub const PTHREAD_CREATE: Self = Self(1);
            pub fn bits(self) -> u32 {
                self.0
            }
        }
        impl core::ops::BitOr for TdFlags {
            type Output = Self;
            fn bitor(self, o: Self) -> Self {
                Self(self.0 | o.0)
            }
        }
        impl core::ops::BitAnd for TdFlags {
            type Output = Self;
            fn bitand(self, o: Self) -> Self {
                Self(self.0 & o.0)
            }
        }
        impl core::ops::Not for TdFlags {
            type Output = Self;
            fn not(self) -> Self {
                Self(!self.0)
            }
        }
    }
    pub struct Tds {
        pub flags: u32,
    }
    pub struct Current {
        tds: Tds,
    }
    pub fn current() -> Current {
        Current {
            tds: Tds { flags: 0 },
        }
    }
    impl Current {
        pub fn id(&self) -> tc::TcsId {
            tc::TcsId(1)
        }
        pub fn td_flags(&self) -> tc::TdFlags {
            tc::TdFlags(self.tds.flags)
        }
        pub fn tds_mut(&mut self) -> &mut Tds {
            &mut self.tds
        }
    }
}
pub mod thread {
    pub use self::native::{Native, Thread};
    #[path = "../sdk/sgx_trts/src/thread/allocator.rs"]
    pub mod allocator;
    #[path = "../sdk/sgx_trts/src/thread/native.rs"]
    pub mod native;
    #[path = "../sdk/sgx_trts/src/thread/task.rs"]
    pub mod task;
    pub mod info {
        std::thread_local! {static CURRENT:std::cell::RefCell<Option<super::Thread>>=const{std::cell::RefCell::new(None)};}
        pub fn set(t: super::Thread) {
            CURRENT.with(|c| *c.borrow_mut() = Some(t));
            crate::TAKEN.store(1, core::sync::atomic::Ordering::SeqCst);
            if crate::MODE.load(core::sync::atomic::Ordering::SeqCst) == 2 {
                while crate::WAITED.load(core::sync::atomic::Ordering::SeqCst) == 0 {
                    std::thread::yield_now();
                }
            }
        }
        pub fn current_thread() -> Option<super::Thread> {
            CURRENT.with(|c| c.borrow().clone())
        }
        pub fn clear() {
            CURRENT.with(|c| *c.borrow_mut() = None);
        }
    }
    pub mod tls {
        pub struct Tls;
        pub struct Active;
        impl Drop for Active {
            fn drop(&mut self) {}
        }
        impl Tls {
            pub fn init() {}
            pub fn activate() -> Active {
                Active
            }
        }
    }
}
use core::{
    alloc::{Allocator, Layout},
    ptr::NonNull,
};
use memory::{AllocationCapability, AllocationOperations, AllocationTicket, OriginOperations};
use std::sync::atomic::{AtomicUsize, Ordering};
static WAITED: AtomicUsize = AtomicUsize::new(0);
static TAKEN: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicUsize = AtomicUsize::new(0);
static FAIL_AT: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_UNDER_LOCK: AtomicUsize = AtomicUsize::new(0);
static RUNS: AtomicUsize = AtomicUsize::new(0);
static DROPS: AtomicUsize = AtomicUsize::new(0);
static WORKERS: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>> =
    std::sync::Mutex::new(Vec::new());
fn allocate(_: AllocationTicket, l: Layout, z: bool) -> Result<NonNull<[u8]>, ()> {
    let n = CALLS.fetch_add(1, Ordering::SeqCst) + 1;
    if FAIL_AT.load(Ordering::SeqCst) == n {
        return Err(());
    }
    let p = if z {
        alloc::alloc::Global.allocate_zeroed(l)
    } else {
        alloc::alloc::Global.allocate(l)
    }
    .map_err(|_| ())?;
    BYTES.fetch_add(l.size(), Ordering::SeqCst);
    Ok(p)
}
unsafe fn deallocate(_: AllocationTicket, p: NonNull<u8>, l: Layout) {
    if sync::HELD.with(|n| n.get()) != 0 {
        CALLBACK_UNDER_LOCK.fetch_add(1, Ordering::SeqCst);
    }
    unsafe { alloc::alloc::Global.deallocate(p, l) };
    BYTES.fetch_sub(l.size(), Ordering::SeqCst);
}
unsafe fn resize(
    t: AllocationTicket,
    p: NonNull<u8>,
    o: Layout,
    n: Layout,
    z: bool,
) -> Result<NonNull<[u8]>, ()> {
    let q = allocate(t, n, z)?;
    unsafe {
        core::ptr::copy_nonoverlapping(p.as_ptr(), q.as_ptr() as *mut u8, o.size().min(n.size()));
        deallocate(t, p, o)
    };
    Ok(q)
}
fn retain(t: AllocationTicket) -> AllocationTicket {
    unsafe { std::sync::Arc::increment_strong_count(t.owner as *const ()) };
    t
}
fn release(t: AllocationTicket) {
    unsafe { std::sync::Arc::decrement_strong_count(t.owner as *const ()) }
}
static OPS: AllocationOperations = AllocationOperations {
    allocate,
    deallocate,
    resize,
};
static ORIGIN: OriginOperations = OriginOperations { retain, release };
fn capability(origin: &std::sync::Arc<()>) -> AllocationCapability {
    unsafe {
        AllocationCapability::from_retained_origin(
            AllocationTicket {
                owner: std::sync::Arc::into_raw(origin.clone()) as usize,
                loan: 0,
            },
            &OPS,
            &ORIGIN,
        )
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn pthread_create_ocall(ret: *mut SgxStatus, _: usize) -> SgxStatus {
    let m = MODE.load(Ordering::SeqCst);
    if m == 1 || m == 2 {
        let w = std::thread::spawn(|| {
            let mut waiter = 0usize;
            thread::native::thread_run((&mut waiter as *mut usize).cast());
        });
        WORKERS.lock().unwrap().push(w);
        while TAKEN.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }
    }
    unsafe {
        *ret = if m == 1 {
            SgxStatus::Unexpected
        } else if m == 2 {
            SgxStatus::Success
        } else {
            SgxStatus::OutOfTcs
        }
    };
    SgxStatus::Success
}
#[unsafe(no_mangle)]
pub extern "C" fn pthread_wait_timeout_ocall(ret: *mut SgxStatus, _: usize, _: u64) -> SgxStatus {
    let first = WAITED.swap(1, Ordering::SeqCst) == 0;
    std::thread::yield_now();
    unsafe {
        *ret = if MODE.load(Ordering::SeqCst) == 2 && first {
            SgxStatus::Unexpected
        } else {
            SgxStatus::Success
        }
    };
    SgxStatus::Success
}
#[unsafe(no_mangle)]
pub extern "C" fn pthread_wakeup_ocall(ret: *mut SgxStatus, _: usize) -> SgxStatus {
    unsafe { *ret = SgxStatus::Success };
    SgxStatus::Success
}
struct Captured(u8);
impl Drop for Captured {
    fn drop(&mut self) {
        DROPS.fetch_add(usize::from(self.0), Ordering::SeqCst);
    }
}
fn reset() {
    assert!(thread::task::pop().is_none());
    for w in WORKERS.lock().unwrap().drain(..) {
        w.join().unwrap();
    }
    for a in [
        &WAITED,
        &TAKEN,
        &MODE,
        &FAIL_AT,
        &CALLS,
        &BYTES,
        &CALLBACK_UNDER_LOCK,
        &RUNS,
        &DROPS,
    ] {
        a.store(0, Ordering::SeqCst);
    }
}
fn factory(a: AllocationCapability) -> Result<thread::Thread, SgxStatus> {
    let captured = Captured(1);
    thread::Thread::new_in(
        move |_| {
            let _keep = &captured;
            RUNS.fetch_add(1, Ordering::SeqCst);
            core::ptr::null_mut()
        },
        core::ptr::null_mut(),
        a,
    )
}
#[test]
fn actual_native_allocation_and_backend_refusals_refund_original_capability() {
    for fail in 1..=3 {
        reset();
        let origin = std::sync::Arc::new(());
        FAIL_AT.store(fail, Ordering::SeqCst);
        assert!(factory(capability(&origin)).is_err());
        assert_eq!(BYTES.load(Ordering::SeqCst), 0);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        assert_eq!(std::sync::Arc::strong_count(&origin), 1);
        assert_eq!(CALLBACK_UNDER_LOCK.load(Ordering::SeqCst), 0);
    }
    reset();
    let origin = std::sync::Arc::new(());
    assert_eq!(
        factory(capability(&origin)).err(),
        Some(SgxStatus::OutOfTcs)
    );
    assert_eq!(BYTES.load(Ordering::SeqCst), 0);
    assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    assert_eq!(std::sync::Arc::strong_count(&origin), 1);
}
#[test]
fn actual_native_consumed_task_with_backend_error_keeps_owner_until_join_and_raw_alias_release() {
    reset();
    MODE.store(1, Ordering::SeqCst);
    let origin = std::sync::Arc::new(());
    let t = factory(capability(&origin)).unwrap();
    let cloned = t.clone();
    let raw = cloned.into_raw();
    let reconstructed = unsafe { thread::Thread::from_raw(raw) };
    assert!(reconstructed == t);
    reconstructed.join().unwrap();
    drop(t);
    for w in WORKERS.lock().unwrap().drain(..) {
        w.join().unwrap();
    }
    assert_eq!(RUNS.load(Ordering::SeqCst), 1);
    assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    assert_eq!(BYTES.load(Ordering::SeqCst), 0);
    assert_eq!(std::sync::Arc::strong_count(&origin), 1);
    assert_eq!(CALLBACK_UNDER_LOCK.load(Ordering::SeqCst), 0);
}

#[test]
fn actual_native_wait_error_after_worker_consumption_preserves_published_start() {
    reset();
    MODE.store(2, Ordering::SeqCst);
    let origin = std::sync::Arc::new(());
    let t = factory(capability(&origin)).unwrap();
    assert_eq!(WAITED.load(Ordering::SeqCst), 1);
    t.join().unwrap();
    for w in WORKERS.lock().unwrap().drain(..) {
        w.join().unwrap();
    }
    assert_eq!(RUNS.load(Ordering::SeqCst), 1);
    assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    assert_eq!(BYTES.load(Ordering::SeqCst), 0);
    assert_eq!(std::sync::Arc::strong_count(&origin), 1);
}
#[test]
fn actual_native_failure_withdraws_own_task_without_consuming_another_creator() {
    reset();
    let origin = std::sync::Arc::new(());
    let a = capability(&origin);
    let other = thread::native::native_adapter_unstarted(a.clone());
    let p = Box::try_new_in(|_| core::ptr::null_mut(), a.clone()).unwrap();
    thread::task::push_in(
        thread::task::Task::new(p, core::ptr::null_mut(), other.clone()),
        a.clone(),
    )
    .unwrap();
    assert_eq!(factory(a.clone()).err(), Some(SgxStatus::OutOfTcs));
    let preserved = thread::task::pop().unwrap();
    assert!(preserved.thread() == &other);
    drop(preserved);
    assert!(thread::task::pop().is_none());
    drop(other);
    drop(a);
    assert_eq!(BYTES.load(Ordering::SeqCst), 0);
    assert_eq!(std::sync::Arc::strong_count(&origin), 1);
    assert_eq!(CALLBACK_UNDER_LOCK.load(Ordering::SeqCst), 0);
}
