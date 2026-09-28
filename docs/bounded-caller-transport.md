# Bounded caller transport substrate

Branch: `feat/bounded-caller-transport`. Base:
`402e5674e2e23f4eb50f02e93635244797eb64f2` on `perf/rpc-event-wakeup`,
following upstream `51c4e8df533cd1fb4721cfb36b57bfc4dda0bf5a`.
Owner approval: package 15 phase 4, caller delivery increment 1.

Ingress responses now move into one producer per TLS session. Each control-loop
turn encrypts at most 32 KiB of body and emits at most 64 KiB of TLS records.
HTTP content lengths and bytes are unchanged. No second whole-response HTTP
buffer or whole-response TLS buffer is constructed. Responses from separate
sessions make round-robin progress, retaining the existing 4 MiB aggregate
channel backlog and 1 MiB shared-message cap.

The opt-in host channel tag `TcpWriteCredit` (0x0c) starts with zero. The host
acknowledges cumulative bytes actually written to that socket. The enclave
tracks sent/written counters with checked arithmetic and a 2 MiB window. An
old, excessive, malformed or overflowing acknowledgement closes the connection;
a duplicate grants no new credit. An untrusted host can lie about socket writes
but cannot change authenticated caller credit, frame authority or object data.
Legacy outbound peer/worker/source sockets do not opt into this host contract.
Local closes acknowledge teardown so the application frees reservations once.
The host and enclave must be deployed together; an old host cannot acknowledge
the new tag and the producer will stop at its bounded window.

Pending plaintext requests have a 16 MiB + 64 KiB aggregate cap. Endpoint
configuration is rechecked as output drains; revocation discards the pending
response. The application separately authorizes every complete caller frame
and enforces its own per-session/global payload budgets. Mini does not create
or cache application authority. Enclave heap size is exposed through the SDK's
public `MmLayout` so admission follows the signed deployment configuration.

Existing bodies are extended, not added: common channel codec/accounting,
host partial-write/drain/teardown, and the native RA-TLS session body. The latter
compares a 5 MiB response byte-for-byte over real TLS, rejects a second response,
and rejects continued output after endpoint revocation. Counts remain common
123, host 27, session 3 (within egress 27).

Working-tree checks: common 123 and host 27 PASS; native TLS session 3 PASS;
SGX HW Release compile/link/sign PASS before the final dispatch-loop cleanup.
These are development observations, not exact-commit or physical qualification.
The parent branch's `docs/bounded-caller-delivery.md` records final commits,
commands, failures, measurements and remaining work. Full physical matrix and
SIM integration are NOT-RUN at this checkpoint.
