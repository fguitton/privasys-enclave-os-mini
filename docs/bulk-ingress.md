# Optional incremental bulk ingress

`register_bulk_ingress_hook` installs one adopter callback during core
initialization, before the ingress server starts. Without that callback, the
ordinary HTTP parser, handler and 16 MiB body limit remain unchanged. Installing
the callback does not negotiate a larger signed window or supply appraisal,
application authority, an aggregate memory profile or an upload decoder.

The callback receives the exact empty-body `HttpRequestHead` and context built
from the enclave-resident TLS session. The exporter, served leaf, endpoint and
accepted evidence must be compared with the adopter's already-appraised Open.
The host connection ID and HTTP path/content headers are routing inputs, not
authority. Return `None` for ordinary handling or a unique
`AdmittedBulkIngress` receiver. Bulk requires exactly one Content-Length and no
Transfer-Encoding. These framing facts come from that same parsed head;
ordinary `None` keeps the existing parser's framing rules.

The optional transport bounds headers to 32 KiB and separate pipelined
lookahead to 64 KiB. Plaintext processing and receiver callbacks each have a
1 MiB service quota, independently of ciphertext length. Each callback gets at
most 16 KiB and never receives bytes beyond the declared body. Header admission,
receive and finish must return promptly without network, storage, appraisal or
worker waits. An absolute monotonic resource deadline begins at acquisition;
tiny progress cannot renew it. Ingress and rotating idle checks cancel expired
resources. This clock cancels resource use and never grants authority.

The receiver owns quarantined data and an independent, non-clone charge owner.
Use `ChargedBytes` or equally strict ownership for every allocation and retained
alias. It uses fallible allocation, precharges simultaneous old/new capacity
before reallocation, and retains monotonic high-water credit until drop. Prefer
preallocating a bounded frame's capacity once. Actual `Vec::capacity` is
reconciled before accepting bytes, but allocator overhead still needs an
explicit resource-profile allowance. A failed allocation never admits payload.
Neither truncating bytes nor draining a Vec refunds capacity.

Mini reports its actual input capacity and bounded plaintext scratch to the
hook. Ordinary input, TLS buffers, header/lookahead, response scratch and queued
output require separate aggregate transport credits in the adopter's memory
profile; this API does not implement or certify that aggregate profile.
`charged_capacity` must report every retained staged charge, including
reallocation high-water. Mini checks it against the accepted staged-capacity
policy after each receive. The callback is trusted composition code, not an
untrusted caller-selectable budget.

Finish consumes the receiver after the exact complete body and receives the
same immutable head plus fresh actual TLS context. The adopter must verify the
whole body and all authenticated inner frames, then atomically recheck current
exporter/endpoint/configuration, withdrawal, owner/fence, contract epoch and
capacity before publishing all or none. Successful receive is only quarantine,
never an acknowledgment. Any retained frames transferred by final admission
must keep their independent charges.

Bulk responses use their own `ChargedBytes` and explicit bounded response
capacity. The producer keeps that charge until encryption finishes or the
response is cancelled. Bulk requests never attach a permit to freely cloned
`HttpRequest` or fall through ordinary dispatch after partial bulk consumption.
Parse/TLS/disconnect/re-attestation/configuration/timeout/finalization errors
cancel the unique receiver and fail the connection. Allocations are freed before
their charges refund. Charge Drop must never reenter Live, session maps,
certificate replacement, storage or network; its independent ledger outlives
those owners. Callbacks run without Mini certificate/module/session-map locks,
but the actual control loop holds the outer `ENCLAVE_STATE` mutex while calling
ingress handling and idle progress. The required order is `ENCLAVE_STATE` then
adopter Live then the independent resource ledger. Callbacks and receiver/charge
Drop must never reenter `crate::state()` directly or through a helper. The direct
native session harness omits that outer lock and does not establish its order.
Allocation-before-refund is proved by source field/drop order; balanced native
ledger counts do not themselves observe allocator deallocation order.

This is an unactivated runtime capability. Application decoder/SDK adoption,
larger signed policy, aggregate fairness/accounting, physical execution and
throughput qualification require separately reviewed work.
