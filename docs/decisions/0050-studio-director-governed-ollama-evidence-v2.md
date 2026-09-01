# ADR-0050: Correct Studio Director-governed observed Ollama evidence as v2

- Status: accepted; implementation partial
- Date: 2026-09-01

## Context

ADR-0046 specified a non-production observed Ollama evidence target. It remains
an immutable historical decision whose exact bytes have SHA-256
`bc4117aa580834984b4847ddb3a81180c6b14f99ba7954f1959abba8f27fbf42`.
Its ordered 86-row vocabulary table, isolated from prose and hashed as the exact
LF-terminated sequence of IDs, has SHA-256
`518cdc4056f8d4ad3cfa9a28b08dcf2324c4b3833f4bc04fd49a9e8b2bc06ed9`.
The prose deliberately names the forbidden
`worldforge_ollama_evidence_custody_handoff_v1` alias outside that table, so a
whole-document search is not a valid registry check.

Subsequent static inspection invalidated three assumptions required by that
target:

1. an empty transient `SupplementaryGroups` assignment does not prove that
   name-service supplementary groups were excluded from the ambient `ollama`
   principal;
2. the ambient executable and model roots were neither copied into dedicated
   World Forge custody nor proven sealed against writable, symlink, or hardlink
   final roots; and
3. the reviewed systemd 255 manager did not provide the proposed transient
   `StandardInputFileDescriptor:h` setter. Its observed descriptor-name property
   cannot substitute for an input setter.

Those are contract defects, not failed provider executions. No service, model,
socket, host account, systemd unit, or inference was touched to reach this
decision.

## Decision

### ADR-0046/v1 is permanently unavailable

The canonical
`world-forge.private.ollama_adr0046_disposition` version-2 correction document
binds the exact ADR bytes, ordered registry, and these exhaustive defect codes:

- `ambient_model_root_custody_unsealed`
- `ambient_release_root_custody_unsealed`
- `nss_supplementary_groups_not_excluded`
- `transient_standard_input_fd_setter_unavailable`

Its availability is permanently `permanently_unavailable`. Production
eligibility, catalog admission, provider execution, provider turns, replay
claims, and pricing claims are false. Migration, conversion, and promotion are
also false: no v1 document or evidence can become v2 evidence. The canonical
content hash is
`ec2fa718852dfc55babd1de180a0e799a87e2542555b231fa88f080873c2e99a`;
the SHA-256 of its complete compact canonical bytes is
`b2367c785c7435d678421fe0abfff2b2a583f123081d3adfbef5255a3642b05d`.

### The v2 foundation policy is a closed immutable document

The canonical
`world-forge.private.ollama_observed_evidence_foundation_policy` version-2
document defines only a correction policy:

- the principal and primary group are exactly `worldforge-ollama-evidence`;
  it is a dedicated non-login principal, admits neither the ambient `ollama`
  account nor name-service supplementary groups, and has no supplementary
  groups; `render` and `video` are explicitly forbidden;
- executable release and model custody each require a copied, byte-manifested,
  sealed World Forge root; ambient, symlink, hardlink, and writable final roots
  are forbidden;
- socket activation uses installed
  `worldforge-ollama-evidence.socket` and
  `worldforge-ollama-evidence.service` units. The socket's exact
  `FileDescriptorName=ollama-http` must match the service's exact
  `StandardInput=fd:ollama-http`; a transient FD setter is forbidden;
- `OLLAMA_NO_CLOUD=1` is exact, parent environment inheritance is forbidden,
  and the listener is numeric IPv4 loopback `127.0.0.1` only. DNS,
  non-loopback addresses, redirects, proxies, and proxy-environment inheritance
  are forbidden;
- the device profile is exactly CPU-only with no accelerator. Supplementary
  accelerator groups, device allow entries, accelerator paths, selected
  accelerator backends, runtime activation, device open, mmap, and ioctl are
  all forbidden; and
- availability remains `unavailable`; production eligibility, catalog
  admission, provider execution, provider turns, replay claims, and pricing
  claims remain false.

The canonical content hash is
`c4fbf98a52896901bb46732935a7fbef462b7369105dab5bffcff381a3968f73`;
the SHA-256 of its complete compact canonical bytes is
`030f2a3432efc21d3f9915cd39575e334c47b24b58770935c5105e8f5d5c1322`.
Validators require exact JSON types and fields, reject bool-as-int and
non-JSON values, validate the outer content hash, and then require byte identity
with the applicable canonical document. The v1 and v2 formats never
cross-accept.

### This release is deliberately pure and contract-only

`worldforge.provider_evidence.ollama_v2` accepts supplied bytes or JSON values
and performs deterministic validation only. It imports no Harness, provider
catalog, worker, EventLog, filesystem, process, socket, systemd, network, model,
SDK, or Studio implementation. It creates no public schema, receipt, catalog
entry, `ProviderAdapter`, worker identity, or runtime effect.

The existing synthetic catalog therefore remains exactly two entries:
`worldforge_conformance_provider` revision 4 and
`worldforge_deterministic_probe_provider` revision 6, both protocol version 3
and non-production. Ollama is not a third entry.

### ADR-0050 is one coupled release train, not one oversized commit

This decision reserves four independently verified release boundaries:

1. **v2 correction-policy foundation** — implemented by this commit;
2. **real evidence controller** — absent;
3. **Studio Director domain, Store, protocol, and UI v7 authority** — absent;
4. **separately authorized host preparation and native observed evidence** —
   absent.

The later Studio authority must bind an authenticated Director decision to an
exact controller plan without putting Ollama into the Harness catalog. Host
preparation must use dedicated copied custody rather than mutate or adopt the
ambient installation. Native evidence must prove the installed socket/service
pair, exact principal/group census, sealed roots, cloud-off loopback route,
no-proxy state, CPU-only device boundary, cleanup, and a real bounded inference.
None of those later requirements is satisfied by the existence of this policy.

## Consequences

- ADR-0046 stays byte-for-byte unchanged and is permanently unavailable.
- The correction policy is functional and deterministic, but it cannot launch,
  observe, authorize, replay, price, or promote a provider turn.
- No synthetic fixture or contract test is native Ollama PASS evidence.
- ADR-0050 remains **PARTIAL**, with `availability: unavailable` and
  `production_eligible: false`, until every later boundary ships and receives
  its own evidence.
- Any future controller or Studio release must consume the exact canonical
  policy rather than restating weaker host assumptions.

## Verification

The strict-TDD record is
[`ollama-observed-evidence-v2-contract-tdd.md`](../evidence/ollama-observed-evidence-v2-contract-tdd.md).
It covers exact source/registry binding, canonical vectors, closed validation,
adversarial drift, package isolation, the unchanged two-entry synthetic
registry, and protected Harness/public bytes. It contains no service start,
process/socket/model execution, host mutation, network access, installation, or
synthetic native PASS claim.
