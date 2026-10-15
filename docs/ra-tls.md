# Remote Attestation TLS

The current protocol uses an ordinary TLS 1.3 handshake followed by a
connection-bound evidence exchange. Quotes are exchanged as evidence, not
embedded in certificates. Retired quote OIDs are rejected.

The verifier checks the served certificate, required configuration OIDs,
report-data binding, quote identity, evidence freshness and configured
appraisal policy before application traffic is admitted. Challenge evidence
binds both the current connection's TLS exporter and its challenge context.
Mutual attestation applies the corresponding peer evidence checks in both
directions; TLS completion alone grants no application authority.

Each attestation-server response must contain a TCB status. The explicit
acceptable-status array adds exceptions to the secure floor (`UpToDate`,
`SWHardeningNeeded`); an empty array permits that floor only. Missing or empty
reports and `Revoked` never pass appraisal.

The wire and binding definitions are maintained in `common/src/attest.rs`;
client verification is in `crates/enclave-os-egress/src/client.rs`, and the
server exchange is in `enclave/src/ratls/server.rs`. See the
[current protocol reference](https://github.com/Privasys/ra-tls-clients/blob/main/docs/ratls-v2.md)
and [OID reference](https://github.com/Privasys/ra-tls-clients/blob/main/docs/oids.md).
