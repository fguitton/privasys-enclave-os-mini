# Selected retained provider and cache profile

This verified build-owned rustls 0.23.45 profile keeps the existing ring algorithm lists and server cache policies (256 sessions and four compression entries). It explicitly uses the pinned nightly allocator API and retains rustls's unsafe-code prohibition. Package manifests, Cargo lock and resolved dependency graph remain unchanged.

The enclave passes the original SDK OwnedAllocator through the minimal owned-hash-map facade and allocator-backed queues before cache backing allocation. The opaque first-party config carrier separately prepays complete concrete Arc metadata layouts and default list buffers. The default unprofiled supplier source is untouched.

Session key, duplicate FIFO key and value copies are fallible allocator-owned vectors. Insertion prepares the copies and reserves collection backings before publishing an entry. Get copies and take transfers the value with its allocator, so a returned value keeps its original origin alive after cache/configuration release. The sole current get/take contract carries this ownership, including both TLS 1.2 and TLS 1.3 decoding consumers. Allocation refusal remains a cache miss or unsuccessful put, without a partial new entry.

The selected ring/std feature graph enables neither certificate compressor, so compression-entry buffers are unreachable; the default four-entry queue is still paid. Certificate, signing and handshake children remain separate owners. This profile alone is not global allocator enforcement or a complete TLS allocation claim. Native adapter tests do not establish selected-target execution.

The actual Mini leaf uses the named PKCS8/P256 constructor. Its pair and signing
key Arc payloads join the current config quote before construction; both backend
requests are fallible. The SPKI DER buffers use the original retained allocator,
and the key exposes a borrowed SPKI for the unchanged certificate/key match.
Malformed current keys and mismatched certificates still refuse. The generic
supplier key APIs retain their standards scope; they are not a fallback from
this selected constructor. Signer Box/signature and record children remain open.
