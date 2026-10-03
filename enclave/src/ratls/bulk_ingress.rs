// Copyright (c) 2026 Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

//! Optional pre-body admission. No registered adopter means ordinary ingress.
//! Callbacks run without Mini certificate/module/session-map locks. They must
//! return promptly and must not do network, storage, appraisal or worker waits.
//! The control loop does hold ENCLAVE_STATE: lock order is STATE -> adopter
//! Live -> independent ledger. Callbacks/receiver/charge Drop must never reenter
//! crate::state(), directly or indirectly. Direct-session tests omit that lock.

use enclave_os_common::{
    ingress::ChargedBytes, modules::RequestContext, protocol::HttpRequestHead,
};
use std::time::Duration;

pub const MAX_BULK_HEADER_BYTES: usize = 32 * 1024;
pub const MAX_BULK_LOOKAHEAD_BYTES: usize = 64 * 1024;
pub const BULK_PLAINTEXT_PIECE_BYTES: usize = 16 * 1024;
/// Plaintext service quota, independent of ciphertext event length.
pub const BULK_PLAINTEXT_TURN_BYTES: usize = 1024 * 1024;

/// Actual enclave session metadata plus separately charged transport capacity.
/// Routing correlation is never an identity. Appraisal/Open/authority checks
/// belong to the adopter and must bind the exporter and selected endpoint.
pub struct BulkIngressContext {
    pub request: RequestContext,
    pub input_capacity: usize,
    pub plaintext_scratch_capacity: usize,
}

/// Unique staged-body and independent permit owner. No Clone/full-Vec escape.
/// Any staged alias must retain its own charge. Cancellation frees allocations
/// before refund and must never lock Live/session/certificate replacement.
/// Its Drop must also never reenter Mini's enclosing ENCLAVE_STATE mutex.
pub trait BulkIngressReceiver: Send {
    /// Actual staged allocation capacities covered by its independent charges.
    /// Include retained aliases and staging overhead in the adopter's profile.
    fn charged_capacity(&self) -> usize;
    /// Quarantined bytes only; successful receive is never ownership/admission.
    fn receive(&mut self, bytes: &[u8]) -> Result<(), &'static str>;

    /// Consume only after the complete exact body. Validate every frame/digest,
    /// then freshly recheck exporter/endpoint/config/owner/fence/contract epoch
    /// and atomically publish all or none. Do not cache header-time authority.
    fn finish(
        self: Box<Self>,
        head: &HttpRequestHead,
        context: &BulkIngressContext,
    ) -> Result<BulkIngressResponse, &'static str>;
}

pub struct AdmittedBulkIngress {
    pub receiver: Box<dyn BulkIngressReceiver>,
    pub max_body_bytes: usize,
    pub max_staged_capacity: usize,
    pub max_response_capacity: usize,
    /// One absolute resource deadline from acquisition; progress never renews.
    /// Elapsed time can cancel a resource but grants no application authority.
    pub resource_timeout: Duration,
}

/// Response capacity stays charged until its unique bounded producer drops.
pub struct BulkIngressResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: ChargedBytes,
}

pub type BulkIngressHook = fn(
    head: &HttpRequestHead,
    context: &BulkIngressContext,
) -> Result<Option<AdmittedBulkIngress>, &'static str>;
