# Retained default provider source

This build-owned source adds a fallible constructor for the exact acquired
rustls ring provider lists. The package manifests, algorithm lists, random
provider and key provider remain the acquired definitions. Original vendor files
are verified and never edited; the output and both Cargo source routes have
independent byte, mode, lock and dependency-graph checks.

The private TLS config carrier admits the actual two Vec layouts and full
provider ArcInner request before construction and retains the charge through
cached config and Session aliases. The selected constructor refuses unexpected
retained Vec capacities. This requested-layout proof excludes allocator-private
metadata and other config, certificate, signing and handshake allocations.

The allocator failure shim is compiled only for native library tests. It arms
one exact constructor request on the current test thread, retains ordinary
System behavior otherwise, and verifies all prepared backing is freed. It does
not select a production global allocator policy.
