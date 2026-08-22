# Supported-host public profile v1

The current candidate is not a compile-time runner identity. A pending profile
contains `pending_authenticated_candidate_descriptor`. A selected profile
contains only the non-authorizing public projection of an opaque
`VerifiedSelectedCandidate`. Runtime admission must match that descriptor.

## Purpose

This contract defines the public identity and lifecycle boundary for
`codexmax-first-party-authoritative-supported-host-runtime-v1`.

The profile has two states.

- `pending_external_identity` contains all product-owned values. Public
  certificate values and the deployment identity are absent.
- `pending_real_tls_handshake_evidence` contains parsed public X.509
  certificate bytes and exact derived metadata. It is not a qualified state.

Source-local code has no `qualified` state, constructor, sentinel, callback,
validator, or attestation promotion path.

A certificate authenticates a principal. It is never fact authority.

## Current public selection and deployment admission compatibility

The profile does not select a compile-time runner. A live operator supplies one
canonical selected-candidate descriptor through inherited descriptors. The
current source-local candidate used by the preservation tests is runner v32
and standalone.36.

- State: `selected_descriptor_verified_non_authorizing`
- Candidate: `codexmax-package-host-runner-v32`
- Archive SHA-256: `905a0c03b348f3050f04299ebdb4ec2111b2ba6a14c016bc61c92aca18a33586`
- Sidecar SHA-256: `029bfb9c32611bc4bb4603d0c2af2163e3e5a7084dffabc835b714192d2d03e0`
- Source identity SHA-256: `ab26e50a4f8bd756fcd95ac69cf6afd53400387736da7d71bc26aed050dd0c06`
- Standalone version: `0.5.0+codex.20260813.standalone.36`
- Standalone manifest SHA-256: `3113670fef8d4dff2e416b8a9a8dd1d6a19aee644bf605edc1a4000a6c3d9a8b`
- Admission authority: `false`

The selection is exact public metadata only. It cannot admit itself. The
profile rejects any predecessor or mixed-version selection.

The current profile is closed to these protocol values.

- Identity type: `bootstrap_bound_deployment_admission_v2`
- Protocol: `supported_host_deployment_admission_v2`
- Bootstrap source: `codexmax-supported-host-deployment-bootstrap-v2`
- Minimum generation: `1`
- Host: `codexmax-package-host-external`

The authenticated deployment transaction must independently bind the selected
descriptor, archive, sidecar, source identity, root, and launched child.

Runner v23 remains named legacy migration history only.

- Candidate: `codexmax-package-host-runner-v23`
- Host: `codexmax-package-host-external`
- Build: `codexmax-package-host-external-t099-v23`
- Runner artifact type: `codexmax_package_host_runner_bundle_v23`
- Archive name: `codexmax-package-host-runner-bundle-v23.tar`
- Manifest name: `codexmax-package-host-runner-bundle-v23.manifest.json`
- Immutable historical runner locator: `orcastrata:historical-package-host-runner:v23:codexmax-package-host-runner-bundle-v23`
- Archive authority: `installer_verified_sidecar_and_protected_service_admission_v1`
- Archive SHA-256: `607eb7c32c7907f6f1b3c289c6dfd0970cf878d5cfa55ecf74b8c2c6dac75925`
- Sidecar SHA-256: `e4d109a2c469663cd86dd74418981a959f3ac1fd916493243a1537a3bdbd1e0e`
- Source identity SHA-256: `4c8bda775cc1757ab9e8c3e6fc380fd85a86ea4557bba22a46e2a4ec179133ab`
- DNS SAN: `codexmax-package-host.local`

Runner v23 retains T098 runner v12 and T071 runner v10 as named predecessor
lineage only. It cannot authorize the next generation. A separately governed
bootstrap verifies the selected descriptors and launched root. A caller
digest, certificate, or runner self-digest cannot create deployment authority.

## Principal map

Six principal labels partition the twelve external operations exactly once.
Each operation has one capability, canonical source ID, and durable namespace.
The source module contains the canonical closed table.

- `first-party-effect-authority-producer-v1`
- `first-party-registered-action-producer-v1`
- `first-party-responses-seals-producer-v1`
- `first-party-catalog-selection-producer-v1`
- `first-party-native-supervision-producer-v1`
- `first-party-recovery-producer-v1`

The registered-action configuration has one action. Its ID is
`codexmax-supported-host-registered-action-v1`.

## Certificate boundary

The parsed certificate set requires one public CA certificate, one public
server certificate, and six public client certificates. The server certificate has
only `serverAuth`. It has the exact DNS SAN. Each client certificate has only
`clientAuth`. All leaf digests are unique. Each issuer matches the CA subject.

The source accepts base64-wrapped DER or PEM X.509 certificate bytes. A strict
DER parser derives the serial, subject, issuer, validity, DNS SAN, EKU, and CA
role. The declared public metadata must match the parsed bytes. Arbitrary bytes
cannot reach a metadata-validated or qualified state.

The source-local parser does not implement cryptographic signature or chain
verification. Therefore, parsed metadata stays nonqualified. Only the future
live package-host receiver can promote trust after it owns a real TLS 1.3
handshake and validates the public chain, server SAN and EKU, client
authentication, and principal leaf.

The closed handshake evidence schema binds the profile and certificate-set
digests, host, service instance, service start, TLS version, SAN, EKU, client
authentication result, server leaf, principal, client peer leaf, observed and expiry times,
request, response, nonce, and receiver receipt. The structural validator cannot
establish receiver provenance. It always returns
`pending_receiver_owned_live_validation`. A certificate remains authentication
evidence only. It has `fact_authority: false`.

The profile rejects caller fields for keys, private material, credentials,
secrets, passwords, tokens, credential locations, endpoints, and environment
values. The fixed public runner target is selection metadata only.

## Lifecycle boundary

The lifecycle module implements only pure checks and command rendering. It does
not install a candidate. It does not read a credential. It does not open a
socket. It does not start or stop a process. It does not write production
persistence.

Before any external-action gate, the lifecycle command parses every required
public JSON map and inherited descriptor map. It requires closed service,
joint-authority, operation-source, supervisor, observation, and service-root
shapes. It also requires one nonempty identifier-only opaque-agent reference.
It rejects extra, missing, duplicate, empty, path-like, or sensitive-looking
values with typed, non-echoing errors.

The lifecycle result uses these pending states when applicable.

- `pending_external_identity`
- `pending_real_tls_handshake_evidence`
- `pending_receiver_owned_live_validation`
- `not_observed_check_only`

Source-local validation proves parsing, schema, identity, mapping, and
command-template behavior only. It does not prove certificate-chain trust, a
real TLS handshake, receiver provenance, service, socket, durable production
store, live receipt, or fourteen-operation journey.
