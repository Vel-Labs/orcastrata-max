# Supported-host deployment bootstrap v3

Status: source-local Darwin launch-proof gate implemented; live proof pending

## Composition

V3 adds only the Darwin `LaunchProofV3` rejection gate. It does not import,
alias, or re-export the R3 bootstrap module or any operational R3 type. It does
not expose a ledger, launch operation, receipt channel, transaction, commit, or
admission type.

The unchanged R3 boundary remains:

```text
receiver-owned LaunchProofV3
          |
          v
pending source-local assessment
          |
          x  no R3 ledger transition

later receiver-owned acceptance
          |
          v
R3 durable ledger -> protected writer receipt -> independent anchor receipt
```

R6 does not implement the later receiver-owned acceptance edge.

## Fail-closed behavior

`assess_darwin_launch_proof_for_r3` can reject unsafe evidence. Otherwise, it
returns `LaunchProofV3Assessment`. This type can represent only a `pending_*`
state. Its authority, ledger-advance, process, pathname, and external-action
flags are fixed to false.

The function does not accept a ledger object. It does not reserve, launch,
write, commit, or issue admission. Expected bindings and replay collections are
rejection inputs only. They are not authority.

## R3 preservation

V3 has no code dependency on the R3 module. R3 stays as a separate downstream
boundary. A later receiver integration must call R3 only after independent
live acceptance. This source-local gate cannot provide that acceptance.

R3 still requires descriptor-based execution. It still raises
`deployment_descriptor_exec_unavailable` before child start when the host does
not expose descriptor-based `execve`. V3 does not add `posix_spawn`, `/dev/fd`,
a pathname fallback, or a native launcher.

## Commit boundary

The existing R3 durable ledger and its distinct protected-writer and
independent-anchor receipts remain the required downstream commit boundary.
V3 does not duplicate that model.

Rollback is a new transaction. It uses the next higher generation. It uses a
fresh nonce. It requires a complete new launch proof. An old proof, nonce,
process instance, service instance, or receipt cannot authorize rollback.

## Proof boundary

R6 proves only closed schema behavior, deterministic pending states, eager
relationship checks, adversary rejection, and absence of an R3 operational
public surface. It does not prove a live
macOS launch, process identity, code identity, filesystem owner, launchd job,
service account, challenge response, ledger commit, or admission.
