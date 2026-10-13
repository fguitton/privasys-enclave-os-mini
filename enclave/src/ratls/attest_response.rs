//! Original attestation response schema with admitted child and final JSON bytes.
use enclave_os_common::allocation::{AllocationLeaseV1, AllocationPoolV1};
use enclave_os_common::attest::{self, AttestResponse};
use std::io::{self, Write};
use std::sync::Arc;

/// Inline borrowed inputs have no authority and do not allocate.
pub(crate) struct ResponseRef<'a> {
    pub(crate) mode: &'a str,
    pub(crate) quote: &'a [u8],
    pub(crate) quote_time: &'a str,
    pub(crate) client_context: Option<&'a [u8]>,
}
impl ResponseRef<'_> {
    fn client_evidence(&self) -> &'static str {
        if self.client_context.is_some() {
            "required"
        } else {
            "none"
        }
    }
    fn working_bytes(&self) -> Option<usize> {
        self.mode
            .len()
            .checked_add("sgx".len())?
            .checked_add(attest::b64_encoded_len(self.quote.len())?)?
            .checked_add(self.quote_time.len())?
            .checked_add(self.client_evidence().len())?
            .checked_add(match self.client_context {
                Some(value) => attest::b64_encoded_len(value.len())?,
                None => 0,
            })
    }
}
/// Fields release the owned schema's child allocations before working credit.
pub(crate) struct PaidResponse {
    response: AttestResponse,
    _working: AllocationLeaseV1,
}
impl PaidResponse {
    pub(crate) fn new(pool: &Arc<AllocationPoolV1>, value: &ResponseRef<'_>) -> Option<Self> {
        let working = pool.reserve_unpublished(value.working_bytes()?)?;
        let response = AttestResponse {
            v: attest::PROTOCOL_VERSION,
            mode: copied(value.mode)?,
            tee: copied("sgx")?,
            quote: encoded(value.quote)?,
            gpu_evidence: None,
            quote_time: copied(value.quote_time)?,
            client_evidence: copied(value.client_evidence())?,
            client_context: match value.client_context {
                Some(value) => Some(encoded(value)?),
                None => None,
            },
            error: None,
        };
        working.activate_release_notification();
        Some(Self {
            response,
            _working: working,
        })
    }
    pub(crate) fn into_body(self, pool: &Arc<AllocationPoolV1>) -> Option<crate::HttpResponseBody> {
        let mut count = Count(Some(0));
        serde_json::to_writer(&mut count, &self.response).ok()?;
        // Working schema remains alive while both complete output and child
        // encodings coexist. Final bytes carry their own original-pool lease.
        let length = count.0?;
        let allocation = pool.reserve_unpublished(length)?;
        let mut writer = Exact {
            bytes: Vec::new(),
            refused: false,
        };
        writer.bytes.try_reserve_exact(length).ok()?;
        if writer.bytes.capacity() != length {
            return None;
        }
        serde_json::to_writer(&mut writer, &self.response).ok()?;
        if writer.refused || writer.bytes.len() != length || writer.bytes.capacity() != length {
            return None;
        }
        allocation.activate_release_notification();
        Some(crate::HttpResponseBody::with_allocation(
            writer.bytes,
            Some(allocation),
        ))
    }
}
fn copied(value: &str) -> Option<String> {
    let mut output = String::new();
    output.try_reserve_exact(value.len()).ok()?;
    if output.capacity() != value.len() {
        return None;
    }
    output.push_str(value);
    Some(output)
}
fn encoded(value: &[u8]) -> Option<String> {
    let length = attest::b64_encoded_len(value.len())?;
    let mut output = Vec::new();
    output.try_reserve_exact(length).ok()?;
    if output.capacity() != length {
        return None;
    }
    output.resize(length, 0);
    if attest::b64_encode_into(value, &mut output)? != length {
        return None;
    }
    // The original base64 engine emits ASCII; conversion keeps the same Vec.
    String::from_utf8(output).ok()
}
// These private sinks never create an io::Error (serde_json boxes it). A
// refused sink discards the rest of this bounded serialization; only its owner
// can inspect the latch, and it must refuse rather than publish partial bytes.
struct Count(Option<usize>);
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.and_then(|count| count.checked_add(bytes.len()));
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Exact {
    bytes: Vec<u8>,
    refused: bool,
}
impl Write for Exact {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.refused {
            match self.bytes.len().checked_add(bytes.len()) {
                Some(end) if end <= self.bytes.capacity() => self.bytes.extend_from_slice(bytes),
                _ => self.refused = true,
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn check() {
    for length in 0..=5 {
        let quote = vec![0xa5; length];
        for context in [None, Some(&[7u8; 32][..])] {
            let value = ResponseRef {
                mode: "challenge\"\\\n雪",
                quote: &quote,
                quote_time: "2026-10-13T00:00Z",
                client_context: context,
            };
            let original = AttestResponse {
                v: attest::PROTOCOL_VERSION,
                mode: value.mode.to_owned(),
                tee: "sgx".to_owned(),
                quote: attest::b64_encode(&quote),
                gpu_evidence: None,
                quote_time: value.quote_time.to_owned(),
                client_evidence: if context.is_some() {
                    "required"
                } else {
                    "none"
                }
                .to_owned(),
                client_context: context.map(attest::b64_encode),
                error: None,
            };
            let original_bytes = serde_json::to_vec(&original).unwrap();
            let working = value.working_bytes().unwrap();
            let short = AllocationPoolV1::new(working - 1).unwrap();
            assert!(PaidResponse::new(&short, &value).is_none());
            assert_eq!(short.used(), 0);
            let maximum = working.checked_add(original_bytes.len()).unwrap();
            let short_body = AllocationPoolV1::new(maximum - 1).unwrap();
            let paid = PaidResponse::new(&short_body, &value).unwrap();
            assert!(paid.into_body(&short_body).is_none());
            assert_eq!(short_body.used(), 0);
            for capacity in [maximum, maximum + 1] {
                let pool = AllocationPoolV1::new(capacity).unwrap();
                let paid = PaidResponse::new(&pool, &value).unwrap();
                assert_eq!(pool.used(), working);
                let body = paid.into_body(&pool).unwrap();
                assert_eq!(&*body, original_bytes);
                assert_eq!(pool.used(), original_bytes.len());
                let payload = crate::HttpResponsePayload::from(body);
                assert_eq!(payload.contiguous().unwrap(), original_bytes);
                assert_eq!(pool.used(), original_bytes.len());
                drop(payload);
                assert_eq!(pool.used(), 0);
            }
            let encoded = attest::b64_encoded_len(quote.len()).unwrap();
            if encoded != 0 {
                let mut short = vec![42; encoded - 1];
                assert!(attest::b64_encode_into(&quote, &mut short).is_none());
                assert!(short.iter().all(|byte| *byte == 42));
            }
        }
    }
    assert!(attest::b64_encoded_len(usize::MAX).is_none());
    let mut count = Count(Some(usize::MAX));
    count.write_all(b"x").unwrap();
    assert!(count.0.is_none());
    let mut exact = Exact {
        bytes: Vec::with_capacity(1),
        refused: false,
    };
    exact.write_all(b"xx").unwrap();
    exact.write_all(b"y").unwrap();
    assert!(exact.refused);
    assert!(exact.bytes.is_empty());
}
