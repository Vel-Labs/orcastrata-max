# Supported-host public provisioning CLI v1

Status: source-local preparation only

## Purpose

The CLI prepares public provisioning input for runner v33. It does not perform
provisioning. It does not install, start, or configure a service.

```text
scaffold-v33 -> incomplete public template -> external fact collection
                                            -> validate -> non-authoritative result
observe-current-process --------------------x no service-role binding
```

## Commands

- `scaffold-v33` emits one deterministic JSON scaffold. The scaffold pins the
  runner v33 archive, sidecar, source identity, standalone.37 manifest, and
  descriptor digests. It uses the exact certificate, service, and descriptor
  role lists from `supported_host_public_provisioning_v1`.
- `observe-current-process` uses public process APIs. It reports the platform,
  process IDs, group IDs, and Python implementation metadata. These values are
  Parent-process facts only. They are not service-role bindings or authority.
- `validate` reads one JSON value from standard input. It rejects private and
  path-like data. It calls `validate_public_provisioning` and checks the
  canonical seal. A valid result remains non-authoritative.

## Incomplete scaffold

Each missing external value is an object with state `unresolved_external` and
a `required_type`. The scaffold has `valid_provisioning_packet: false`,
`authority_minted: false`, and `production_ready: false`. The validator must
reject the scaffold. An operator must replace every unresolved value and pass
only the completed `provisioning_template` object to `validate`.

## Safety boundary

The CLI does not read files, credentials, private keys, keychains, browser
profiles, system configuration, or network resources. It does not accept an
input file option. It does not write files. It does not perform installation,
service control, certificate generation, account creation, or descriptor
binding. A passing result proves only closed public metadata validation.
