# Selected retained provider and cache profile

This verified build-owned rustls 0.23.45 profile keeps the existing ring algorithm lists and server cache policies (256 sessions and four compression entries). It explicitly uses the pinned nightly allocator API and retains rustls's unsafe-code prohibition. Package manifests, Cargo lock and resolved dependency graph remain unchanged.

The enclave passes the original SDK OwnedAllocator through the minimal owned-hash-map facade and allocator-backed queues before cache backing allocation. The opaque first-party config carrier separately prepays complete concrete Arc metadata layouts and default list buffers. The default unprofiled supplier source is untouched.

Cache entry byte copies/returns and certificate, signing and handshake children remain separate owners. This profile alone is not global allocator enforcement or a complete TLS allocation claim.
