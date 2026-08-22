# Execution Preview

- Outcome: <observable result>
- Scope and writes: <read scope; write scope; explicit exclusions>
- External calls: <providers, network, installs, credentials, destructive
  actions, push, publication, or none>
- Billing and fallback: <billing basis; token limit; fallback route or none;
  no silent metered fallback>
- Validation: <repository-native checks; independent verification>
- Stop rule: <acceptance oracle, tranche boundary, failure threshold, or
  external condition>

## Authority Decision

- Existing authority reused: <receipt and exact boundary, or none>
- New or expanded authority: <approval needed with reason, or none>
- External route preflight: <required before every dispatch, pending, passed,
  failed, or not_applicable>
- Operator action: <proceed, answer material question, authorize expansion,
  inspect, or wait>

Detailed goal, assignment, route, evidence, validation, and closeout packets are
generated internally after the preview and applicable authority gates. They are
linked from durable journey state instead of being requested from the operator.
