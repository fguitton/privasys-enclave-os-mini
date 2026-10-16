//! Caller-admitted JSON parser backing and visitor-owned text.
//! The supplied parser must use the admitted scratch and an allocation-free
//! syntax-error representation. This owner does not bless arbitrary parsers.
pub(crate) mod fields;

use crate::allocation::{AllocationLeaseV1, AllocationPoolV1};
use alloc::{string::String, sync::Arc, vec::Vec};
use core::{fmt, ops::Deref};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    Unavailable,
}

/// Parser storage is destroyed before its original-pool backing credit.
pub struct AdmittedParser<P> {
    parser: P,
    _allocation: Option<AllocationLeaseV1>,
}
impl<P> AdmittedParser<P> {
    /// Admit and allocate the exact scratch requested by the actual parser.
    /// The constructor must adopt this backing without copying or growing it.
    ///
    /// # Errors
    /// Returns `Unavailable` when admission, exact backing allocation or adoption fails.
    pub fn new(
        pool: &Arc<AllocationPoolV1>,
        capacity: usize,
        construct: impl FnOnce(Vec<u8>) -> Option<P>,
    ) -> Result<Self, Refusal> {
        let allocation = reserve(pool, capacity)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| Refusal::Unavailable)?;
        if bytes.capacity() != capacity {
            return Err(Refusal::Unavailable);
        }
        let parser = construct(bytes).ok_or(Refusal::Unavailable)?;
        publish(allocation.as_ref());
        Ok(Self {
            parser,
            _allocation: allocation,
        })
    }
    pub fn parser_mut(&mut self) -> &mut P {
        &mut self.parser
    }
}

/// Unescaped input is borrowed; escaped text owns its independently paid copy.
/// Text backing drops before its allocation credit and cannot be cloned unpaid.
pub struct Text<'a> {
    backing: TextBacking<'a>,
    _allocation: Option<AllocationLeaseV1>,
}
enum TextBacking<'a> {
    Borrowed(&'a str),
    Owned(String),
}
impl<'a> Text<'a> {
    /// Borrow text for the lifetime of its original request body.
    #[must_use]
    pub fn borrowed(value: &'a str) -> Self {
        Self {
            backing: TextBacking::Borrowed(value),
            _allocation: None,
        }
    }
    /// Copy escaped text into independently admitted exact-capacity backing.
    ///
    /// # Errors
    /// Returns `Unavailable` before copying when admission or allocation fails.
    pub fn copy(pool: &Arc<AllocationPoolV1>, value: &str) -> Result<Self, Refusal> {
        let allocation = reserve(pool, value.len())?;
        let mut text = String::new();
        text.try_reserve_exact(value.len())
            .map_err(|_| Refusal::Unavailable)?;
        if text.capacity() != value.len() {
            return Err(Refusal::Unavailable);
        }
        text.push_str(value);
        publish(allocation.as_ref());
        Ok(Self {
            backing: TextBacking::Owned(text),
            _allocation: allocation,
        })
    }
    pub fn as_str(&self) -> &str {
        match &self.backing {
            TextBacking::Borrowed(value) => value,
            TextBacking::Owned(value) => value,
        }
    }
}
impl Default for Text<'_> {
    fn default() -> Self {
        Self::borrowed("")
    }
}
impl Deref for Text<'_> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}
impl fmt::Debug for Text<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), formatter)
    }
}
fn reserve(
    pool: &Arc<AllocationPoolV1>,
    bytes: usize,
) -> Result<Option<AllocationLeaseV1>, Refusal> {
    if bytes == 0 {
        Ok(None)
    } else {
        pool.reserve_unpublished(bytes)
            .map(Some)
            .ok_or(Refusal::Unavailable)
    }
}
fn publish(allocation: Option<&AllocationLeaseV1>) {
    if let Some(allocation) = allocation {
        allocation.activate_release_notification();
    }
}

impl AsRef<str> for Text<'_> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
