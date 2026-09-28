# Shared memory64 component profile

The canonical profile is `honest-s2-x86_64-sgx-memory64-v2`, schema 3. It pins
the Wasmtime fork at its v49.0.1 backports, whose fuel fixes the fuel schedule
`wasmtime-47-default-fuel-v2` names. Both complementary Cargo roles use
identical descriptor bytes. Memory64 canonical pointers/layouts, the patched
source manifest, movable memory and a 1-TiB per-memory ceiling are authenticated.
The initial reservation remains 4 MiB, with 1 MiB growth headroom. Fuel, epochs,
explicit bounds checks, no CoW and the conservative native target remain enabled.

Wasmtime's core memory64 support is insufficient for WIT components. The
synchronous canonical ABI change is the `memory64` branch of
`fguitton/honest-wasmtime`, on the pinned Teaclave SGX port: 64-bit pointers
and lengths, then native field offsets advanced in `usize` so absolute
addresses above 4 GiB neither abort the host nor misplace dynamic record and
tuple fields. The reviewed patches in `patches/wasm64` cover component
encoding/validation and Rust guest binding generation.

These trees are path dependencies, outside Cargo's lockfile checksums.
`sources.json` pins the fork revision, the exact upstream commits and patch
digests, and the digest of every file each materialized tree holds.
`scripts/acquire-wasm64.py` reconstructs the sources; `--verify-only` checks the
file digests offline, so an edit hidden from git by index flags, filters,
replace references or excludes is refused. Configuring Mini with CMake and the
guest builder both require it.
Host workspace manifests select these patches. Guest-only manifests deliberately
do not inherit unused host patches, which would destabilize locked builds.

The Wasmtime fork's closed feature rejects every memory32/shared memory in a
component and rejects unsupported async/GC canonical options. Its serialization
marker prevents old and new AOT artifacts being interchanged, even if an embedding
disables package-version checks. `new_store` installs a store-owned memory limiter
without adding runtime authority to the application context.

The SGX platform still eagerly allocates data mappings from the enclave heap.
This branch checks alignment arithmetic, corrects the remap C ABI to three
arguments, refuses code-pool fallback to non-executable heap memory, and fails
execution protection requests for such heap pages. A large linear memory is not
cheap virtual memory here, and growth past the reservation copies the whole
memory, uncharged by fuel. Account for the enclave heap, simultaneous stores,
code-pool capacity, SQL buffers and temporary old/new allocations during growth.
The existing small SIM heaps do not prove the intended hardware memory budget.

The core probe namespace `memory64_proposal` supplies a bounded explicit-file
harness in the matching EHDS branch. Its eight tests cover core admission,
AOT-only execution, budgets, high pointers, fuel, epochs and, typed and dynamic,
a string, a tuple return, spilled parameters and a host import result above
4 GiB. The real admission component tests records, lists, variants
and realloc. Existing shared-profile test identities are retained and extended:
six native AOT tests and five native runtime-role tests. SGX target compilation
and native tests are distinct from SGX simulation and physical qualification.

wasm-tools and wit-bindgen have no writable fork yet, so they stay reviewed
patches on immutable upstream revisions.
