//! Exact SDK fallible allocator under an explicit test-only NULL System backend.
//! No GlobalAlloc is installed and no production infallible allocation is changed.
#![feature(allocator_api, slice_ptr_get)]
extern crate self as sgx_types;
#[path = "sdk/sgx_types/src/memory.rs"]
pub mod memory;
mod sdk_alloc {
    pub struct System;
    pub static FAIL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    pub static FREED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    unsafe impl std::alloc::GlobalAlloc for System {
        unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
            if FAIL.load(std::sync::atomic::Ordering::Acquire) {
                core::ptr::null_mut()
            } else {
                unsafe { std::alloc::GlobalAlloc::alloc(&std::alloc::System, l) }
            }
        }
        unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
            unsafe { std::alloc::GlobalAlloc::dealloc(&std::alloc::System, p, l) };
            FREED.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
    }
    #[path = "../sdk/sgx_alloc/src/fallible.rs"]
    pub mod fallible;
}
use sdk_alloc::fallible::{AllocationTicket, FallibleAllocationHooks, FallibleSystem};
use std::{
    alloc::{AllocError, Allocator, Layout},
    sync::atomic::{AtomicUsize, Ordering},
};
static USED: AtomicUsize = AtomicUsize::new(0);
static CANCELLED: AtomicUsize = AtomicUsize::new(0);
static RELEASED: AtomicUsize = AtomicUsize::new(0);
fn admit(t: AllocationTicket, l: Layout) -> Result<AllocationTicket, AllocError> {
    USED.fetch_add(l.size(), Ordering::AcqRel);
    Ok(t)
}
fn cancel(t: AllocationTicket, l: Layout) {
    assert_eq!((t.owner, t.loan), (17, 29));
    USED.fetch_sub(l.size(), Ordering::AcqRel);
    CANCELLED.fetch_add(1, Ordering::AcqRel);
}
fn release(t: AllocationTicket, l: Layout) {
    assert_eq!((t.owner, t.loan), (17, 29));
    assert!(sdk_alloc::FREED.load(Ordering::Acquire) > 0);
    USED.fetch_sub(l.size(), Ordering::AcqRel);
    RELEASED.fetch_add(1, Ordering::AcqRel);
}
static HOOKS: FallibleAllocationHooks = FallibleAllocationHooks {
    admit,
    release,
    cancel,
};
fn reset() {
    for a in [&USED, &CANCELLED, &RELEASED, &sdk_alloc::FREED] {
        a.store(0, Ordering::Release);
    }
    sdk_alloc::FAIL.store(false, Ordering::Release);
}
fn allocator() -> FallibleSystem {
    unsafe {
        FallibleSystem::new(
            &HOOKS,
            AllocationTicket {
                owner: 17,
                loan: 29,
            },
        )
    }
}
#[test]
fn actual_sdk_backend_null_cancels_admission_without_published_release() {
    reset();
    sdk_alloc::FAIL.store(true, Ordering::Release);
    assert!(allocator().allocate(Layout::new::<[u64; 4]>()).is_err());
    assert_eq!(USED.load(Ordering::Acquire), 0);
    assert_eq!(CANCELLED.load(Ordering::Acquire), 1);
    assert_eq!(RELEASED.load(Ordering::Acquire), 0);
    assert_eq!(sdk_alloc::FREED.load(Ordering::Acquire), 0);
}
#[test]
fn actual_sdk_resize_backend_null_preserves_original_header_bytes_and_final_refund() {
    reset();
    let a = allocator();
    let old = Layout::new::<[u64; 4]>();
    let new = Layout::new::<[u64; 8]>();
    let p = a.allocate_zeroed(old).unwrap();
    let pointer = p.cast::<u8>();
    unsafe {
        pointer.as_ptr().write_bytes(0x5a, old.size());
    }
    let before = USED.load(Ordering::Acquire);
    sdk_alloc::FAIL.store(true, Ordering::Release);
    assert!(unsafe { a.grow(pointer, old, new) }.is_err());
    assert_eq!(USED.load(Ordering::Acquire), before);
    assert_eq!(CANCELLED.load(Ordering::Acquire), 1);
    assert_eq!(RELEASED.load(Ordering::Acquire), 0);
    assert!(
        unsafe { std::slice::from_raw_parts(pointer.as_ptr(), old.size()) }
            .iter()
            .all(|x| *x == 0x5a)
    );
    unsafe { a.deallocate(pointer, old) };
    assert_eq!(USED.load(Ordering::Acquire), 0);
    assert_eq!(RELEASED.load(Ordering::Acquire), 1);
}
