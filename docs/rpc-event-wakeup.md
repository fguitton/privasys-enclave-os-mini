# RPC dispatcher event wake-up

Branch: `perf/rpc-event-wakeup`. Base:
`51c4e8df533cd1fb4721cfb36b57bfc4dda0bf5a`.
Owner approval: package 15 phase 4, 28 September 2026.

Both control and execution dispatchers previously polled through the same
one-millisecond sleep. The notification OCALL did nothing. Each consumer now
has an independent pending bit protected by a shared mutex/condition variable.
The unchanged argument-free OCALL signals both consumers after queue publication.
A notification before waiting remains pending; waiting atomically unlocks the
predicate mutex; spurious wakes recheck it. Signals coalesce per consumer, not
across consumers. Queue draining occurs outside the notification mutex.

Main shutdown, the Shutdown RPC and proxy credit exhaustion all wake sleeping
consumers. The shutdown predicate uses release/acquire ordering. The mutex holds
no application state, and its poison recovery preserves the notification bits.
Enclave code, EDL, queue credits, RPC identities, late-response rejection and
fences are unchanged. Notification is an untrusted scheduling hint.

Three new native host tests exercise the empty-queue/before-wait interleaving
for both roles, spurious notification, and shutdown (including subsequent waits).
The host inventory moves from 24 to 27; common remains 123. The parent repository
reconciles its executable guard and current documentation in the gitlink change.
Exact committed-source checks and hardware diagnostics are recorded in the
parent's `docs/bft-caller-transfer.md` handoff. Hardware results remain diagnostic;
no release or qualification evidence is claimed by this change.
