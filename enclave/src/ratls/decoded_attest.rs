//! Decoded request bytes owned separately from JSON input and retained evidence.
use enclave_os_common::allocation::{AllocationLeaseV1, AllocationPoolV1};
use enclave_os_common::attest;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    Invalid,
    Unavailable,
}
/// The buffer is released before its original-pool allocation lease.
pub(crate) struct Decoded {
    bytes: Vec<u8>,
    _allocation: Option<AllocationLeaseV1>,
}
impl Decoded {
    pub(crate) fn new(pool: &Arc<AllocationPoolV1>, encoded: &str) -> Result<Self, Refusal> {
        let capacity = attest::b64_decoded_capacity(encoded);
        let allocation = if capacity == 0 {
            None
        } else {
            Some(
                pool.reserve_unpublished(capacity)
                    .ok_or(Refusal::Unavailable)?,
            )
        };
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| Refusal::Unavailable)?;
        if bytes.capacity() != capacity {
            return Err(Refusal::Unavailable);
        }
        bytes.resize(capacity, 0);
        let length = attest::b64_decode_into(encoded, &mut bytes).ok_or(Refusal::Invalid)?;
        bytes.truncate(length);
        if let Some(allocation) = &allocation {
            allocation.activate_release_notification();
        }
        Ok(Self {
            bytes,
            _allocation: allocation,
        })
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl core::ops::Deref for Decoded {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}
#[cfg(test)]
pub(super) fn check() {
    for input in [
        "", "=", "Zg", "Zg=", "Zg===", "Zm8", "Zm9v", "Zm9vYg", "!", "Z", "Zg=x", "雪", "-_8",
    ] {
        let original = attest::b64_decode(input);
        let capacity = attest::b64_decoded_capacity(input);
        let pool = AllocationPoolV1::new(capacity.max(1)).unwrap();
        let actual = Decoded::new(&pool, input);
        match (actual, original) {
            (Ok(actual), Ok(original)) => {
                assert_eq!(actual.bytes(), original);
                assert_eq!(pool.used(), capacity);
                drop(actual);
            }
            (Err(Refusal::Invalid), Err(_)) => {}
            _ => panic!("decoder acceptance differs from the original engine"),
        }
        assert_eq!(pool.used(), 0);
        if capacity > 1 {
            let short = AllocationPoolV1::new(capacity - 1).unwrap();
            assert!(matches!(
                Decoded::new(&short, input),
                Err(Refusal::Unavailable)
            ));
            assert_eq!(short.used(), 0);
        }
        let mut output = vec![0xa5; capacity.saturating_sub(1)];
        if capacity > 0 {
            assert_eq!(attest::b64_decode_into(input, &mut output), None);
            assert!(output.iter().all(|value| *value == 0xa5));
        }
    }
    let capacity = attest::b64_decoded_capacity("Zg");
    for maximum in [capacity, capacity + 1] {
        let pool = AllocationPoolV1::new(maximum).unwrap();
        let value = Decoded::new(&pool, "Zg").unwrap();
        assert_eq!(value.bytes(), b"f");
        assert_eq!(pool.used(), capacity);
        drop(value);
        assert_eq!(pool.used(), 0);
    }
}
