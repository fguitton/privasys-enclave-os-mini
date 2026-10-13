//! Allocation-free one-time publication for the fixed function-pointer table.
use super::OcallVtable;
use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicU8, Ordering},
};

const EMPTY: u8 = 0;
const INSTALLING: u8 = 1;
const READY: u8 = 2;

/// Duplicate or still-installing registration; contains no owned payload.
#[derive(Debug)]
pub(super) struct RegistrationRefused;

pub(super) struct OcallSlot {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<OcallVtable>>,
}
// SAFETY: exactly one CAS winner may write, and writes before Release READY.
// Readers access the immutable table only after an Acquire READY load. All
// table fields are function pointers (Send + Sync); no callback runs here.
unsafe impl Sync for OcallSlot {}
impl OcallSlot {
    pub(super) const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
    pub(super) fn set(&self, value: OcallVtable) -> Result<(), RegistrationRefused> {
        if self
            .state
            .compare_exchange(EMPTY, INSTALLING, Ordering::Acquire, Ordering::Acquire)
            .is_err()
        {
            return Err(RegistrationRefused);
        }
        // SAFETY: sole winner; no user code, heap allocation or fallible work
        // occurs between this claim and publication. This slot is never reset.
        unsafe {
            (*self.value.get()).write(value);
        }
        self.state.store(READY, Ordering::Release);
        Ok(())
    }
    pub(super) fn get(&self) -> Option<&OcallVtable> {
        if self.state.load(Ordering::Acquire) != READY {
            return None;
        }
        // SAFETY: Acquire observed complete initialization, with no future writer.
        Some(unsafe { (&*self.value.get()).assume_init_ref() })
    }
}

#[cfg(test)]
pub(crate) fn check() {
    fn table(marker: fn() -> Result<u64, i32>) -> OcallVtable {
        OcallVtable {
            net_tcp_listen: |_, _| Err(-1),
            net_tcp_accept: |_| Err(-1),
            net_tcp_connect: |_, _| Err(-1),
            net_send: |_, _| Err(-1),
            net_recv: |_, _| Err(-1),
            net_close: |_| {},
            kv_store_put: |_, _, _| Err(-1),
            kv_store_get: |_, _| Err(-1),
            kv_store_delete: |_, _| Err(-1),
            kv_store_list_keys: |_, _| Err(-1),
            kv_store_write_batch: |_, _| Err(-1),
            kv_store_multi_get: |_, _| Err(-1),
            kv_store_scan: |_, _, _, _| Err(-1),
            get_current_time: marker,
            log: |_, _| {},
            cert_store_register: |_| {},
            cert_store_unregister: |_| false,
        }
    }
    fn first() -> Result<u64, i32> {
        Ok(11)
    }
    fn second() -> Result<u64, i32> {
        Ok(22)
    }
    let installing = OcallSlot::new();
    assert!(installing.get().is_none());
    installing
        .state
        .compare_exchange(EMPTY, INSTALLING, Ordering::Acquire, Ordering::Acquire)
        .unwrap();
    assert!(installing.get().is_none());
    assert!(installing.set(table(first)).is_err());
    assert_eq!(installing.state.load(Ordering::Relaxed), INSTALLING);

    let slot = OcallSlot::new();
    let barrier = std::sync::Barrier::new(2);
    let (one, two) = std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            barrier.wait();
            slot.set(table(first)).is_ok()
        });
        let two = scope.spawn(|| {
            barrier.wait();
            slot.set(table(second)).is_ok()
        });
        (one.join().unwrap(), two.join().unwrap())
    });
    assert_ne!(one, two);
    let current = slot.get().unwrap();
    assert_eq!((current.get_current_time)(), Ok(if one { 11 } else { 22 }));
    assert_eq!((current.net_tcp_listen)(0, 0), Err(-1));
    assert!(!(current.cert_store_unregister)("unchanged"));
    assert!(slot.set(table(if one { second } else { first })).is_err());
    assert!(core::ptr::eq(current, slot.get().unwrap()));
    assert_eq!(
        (slot.get().unwrap().get_current_time)(),
        Ok(if one { 11 } else { 22 })
    );
}
