//! Caller-admitted JSON parser backing and visitor-owned text.
//! The supplied parser must use the admitted scratch and an allocation-free
//! syntax-error representation. This owner does not bless arbitrary parsers.
pub(crate) mod fields;
/// Original-pool sequence backing for parsed JSON arrays and typed lists.
pub mod sequence;
/// Parsed JSON values with admitted child backings.
pub mod value;
/// Shared current parser for retained JWT claim trees.
#[cfg(feature = "request-json-parser")]
pub mod parse;

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
/// Crate-local transfer: backing always drops before its original field credit.
pub(crate) struct OwnedText {
    pub(crate) value: String,
    pub(crate) credit: Option<AllocationLeaseV1>,
}
impl Text<'_> {
    pub(crate) fn into_owned(self) -> Result<OwnedText, Refusal> {
        let value = match self.backing {
            TextBacking::Owned(value) => value,
            TextBacking::Borrowed("") => String::new(),
            TextBacking::Borrowed(_) => return Err(Refusal::Unavailable),
        };
        Ok(OwnedText {
            value,
            credit: self._allocation,
        })
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

impl core::borrow::Borrow<str> for Text<'_> {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}
impl PartialEq for Text<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for Text<'_> {}
impl PartialOrd for Text<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Text<'_> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}
impl serde::Serialize for Text<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

struct DisplayLength(usize);
impl fmt::Write for DisplayLength {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0 = self.0.checked_add(value.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}
struct DisplayBacking<'a> {
    text: &'a mut String,
    length: usize,
}
impl fmt::Write for DisplayBacking<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let length = self.text.len().checked_add(value.len()).ok_or(fmt::Error)?;
        if length > self.length {
            return Err(fmt::Error);
        }
        self.text.push_str(value);
        Ok(())
    }
}
impl Text<'_> {
    /// Format deterministic allocation-free input into exactly admitted backing.
    /// The display implementation itself remains responsible for its own work.
    /// # Errors
    /// Refuses overflow, admission/allocation failure or a changed second rendered length.
    pub fn display(
        pool: &Arc<AllocationPoolV1>,
        value: &(impl fmt::Display + ?Sized),
    ) -> Result<Self, Refusal> {
        let mut length = DisplayLength(0);
        fmt::write(&mut length, format_args!("{value}")).map_err(|_| Refusal::Unavailable)?;
        let allocation = reserve(pool, length.0)?;
        let mut text = String::new();
        text.try_reserve_exact(length.0)
            .map_err(|_| Refusal::Unavailable)?;
        if text.capacity() != length.0 {
            return Err(Refusal::Unavailable);
        }
        fmt::write(
            &mut DisplayBacking {
                text: &mut text,
                length: length.0,
            },
            format_args!("{value}"),
        )
        .map_err(|_| Refusal::Unavailable)?;
        if text.len() != length.0 {
            return Err(Refusal::Unavailable);
        }
        publish(allocation.as_ref());
        Ok(Self {
            backing: TextBacking::Owned(text),
            _allocation: allocation,
        })
    }
}

/// Current enclave startup configuration with retained JSON backing.
pub mod configuration;
