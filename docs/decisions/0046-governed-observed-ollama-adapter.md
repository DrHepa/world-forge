# ADR-0046: Govern one non-production observed Ollama candidate

- Status: accepted
- Date: 2026-08-29

## Context

ADRs 0038 and 0045 expose exactly two code-owned synthetic runtimes and one
synthetic service. They remain test-only conformance fixtures and
`production_eligible: false`; they cannot satisfy a real-provider milestone.
Static inspection found a local Ollama installation and model, but it has not
proved causal peer ownership, vendor protocol coverage, selected runner/backend,
loaded model bytes, cancellation, logging, telemetry or egress. This decision
therefore specifies an exact evidence target, not an executable or production
adapter.

## Decision

### Closed non-production vocabulary

Ollama is separate from the two-entry synthetic registry and from the current
`ProviderRuntimeSpec`, production catalog, usage and pricing vocabulary. This
ADR defines only these private exact data documents:

| Document | Exact ID | Hash authority |
|---|---|---|
| installation observation | `worldforge_ollama_installation_observation_v1` | canonical installation document |
| model lock | `worldforge_ollama_model_lock_v1` | manifest plus every blob identity |
| cloud-off candidate execution profile | `worldforge_ollama_cloud_off_candidate_v1` | static pre-authorized execution inputs and recipe policy |
| evidence controller plan | `worldforge_ollama_evidence_controller_plan_v1` | fixed logical-main scenario authority and non-user request catalog |
| scenario plan | `worldforge_ollama_evidence_scenario_plan_v1` | exactly one finite facet/scenario operation |
| systemd policy | `worldforge_ollama_evidence_systemd_policy_v1` | exact PID1 properties, methods, credentials, device and retention rules |
| operation lease policy | `worldforge_ollama_operation_lease_policy_v1` | exact lease derivation and manager-cleanup binding |
| systemd unit recipe | `worldforge_ollama_systemd_unit_recipe_v1` | one exact operation, timer or static-action instance recipe |
| native process recipe | `worldforge_ollama_native_process_recipe_v1` | one exact broker executable/argv/environment/credential recipe |
| candidate subgroup recipe | `worldforge_ollama_candidate_subgroup_recipe_v1` | one exact systemd-owned candidate cgroup and limits recipe |
| candidate recipe policy | `worldforge_ollama_candidate_recipe_policy_v1` | static operation-recipe derivation rules |
| final candidate recipe | `worldforge_ollama_candidate_recipe_v1` | lease-derived profile and launcher binding |
| evidence authorization | `worldforge_ollama_evidence_authorization_v1` | one identity-registered human decision capability |
| custody policy | `worldforge_ollama_evidence_custody_policy_v1` | broker, domain-kill and lifetime contract |
| custody proof | `worldforge_ollama_evidence_custody_proof_v1` | sacrificial non-provider systemd/main-loss/timer proof |
| operation lease | `worldforge_ollama_evidence_operation_lease_v1` | outer broker-plus-candidate owner-death contract |
| custody handoff offer | `worldforge_ollama_evidence_custody_handoff_offer_v1` | authenticated logical-role and descriptor-fingerprint offer |
| custody handoff acceptance | `worldforge_ollama_evidence_custody_handoff_acceptance_v1` | authenticated receiver-slot and retained-pidfd acceptance |
| handoff-key acceptance | `worldforge_ollama_handoff_key_acceptance_v1` | authenticated code-2 acceptance of the one-use handoff key seed |
| execution owner | `worldforge_ollama_evidence_execution_owner_v1` | durable execution/recovery owner epoch and fence |
| Studio transition event payload | `worldforge_ollama_studio_transition_event_payload_v1` | acyclic source/cause and ordered target-body transition record |
| Studio transition target body | `worldforge_ollama_transition_target_body_v1` | event-free target preimage and backward-only sibling-body edges |
| owner cutoff | `worldforge_ollama_owner_cutoff_v1` | conservative owner-loss or authenticated-revocation interval |
| recovery fence | `worldforge_ollama_recovery_fence_document_v1` | acyclic owner/recovery takeover fence |
| candidate release gate | `worldforge_ollama_evidence_candidate_release_v1` | inert-to-released/fired atomic custody state |
| release-gate snapshot | `worldforge_ollama_release_gate_snapshot_v1` | directional main-to-broker effect admission |
| release-gate snapshot acceptance | `worldforge_ollama_release_gate_snapshot_acceptance_v1` | directional broker-to-main acceptance and clock observation |
| candidate-configuration offer | `worldforge_ollama_candidate_configuration_offer_v1` | authenticated post-admission recipe disclosure |
| candidate-configuration acceptance | `worldforge_ollama_candidate_configuration_acceptance_v1` | authenticated broker acceptance of exact recipe bytes |
| candidate-configuration payload | `worldforge_ollama_candidate_configuration_payload_v1` | bounded exact configuration bytes embedded by the authenticated offer |
| broker operation result | `worldforge_ollama_broker_operation_result_v1` | content-free effect/result observation |
| broker-result payload | `worldforge_ollama_broker_result_payload_v1` | closed content-free result body embedded by the authenticated result |
| broker terminal | `worldforge_ollama_broker_terminal_v1` | content-free final broker state before sentinel exit |
| broker control ACK | `worldforge_ollama_broker_control_ack_v1` | authenticated result/terminal receipt |
| fork-safe launcher policy | `worldforge_ollama_fork_safe_launcher_v1` | fixed native fork/exec and child-FD contract |
| fork-window observation | `worldforge_ollama_fork_window_observation_v1` | key, signal, callback and descriptor inheritance proof |
| launcher procfs mount identity | `worldforge_ollama_launcher_procfs_mount_identity_v1` | exact procfs mount used by the pre-exec FD census |
| launcher proc-fd directory identity | `worldforge_ollama_launcher_proc_fd_directory_identity_v1` | exact opened and closed `/proc/<pid>/fd` census directory |
| native broker policy | `worldforge_ollama_native_single_thread_broker_policy_v1` | static one-TID/no-thread broker contract |
| native broker observation | `worldforge_ollama_native_single_thread_broker_v1` | exact one-TID broker and no-thread authority |
| broker ready | `worldforge_ollama_broker_ready_v1` | authenticated native-broker readiness record on descriptor 198 |
| listener observation | `worldforge_ollama_listener_observation_v1` | exact listener result or drift observation |
| deadline-tombstone key | `worldforge_ollama_deadline_tombstone_key_document_v1` | independent attempt/gate/epoch/deadline key identity |
| deadline tombstone | `worldforge_ollama_evidence_deadline_fired_v1` | immutable PID1-action cutoff observation |
| deadline-action lifecycle | `worldforge_ollama_evidence_deadline_action_lifecycle_v1` | not-created, armed, fire-committed and invoked-terminal state |
| deadline-action reboot abandonment | `worldforge_ollama_deadline_action_reboot_abandonment_v1` | immutable old-boot pending action abandoned without reconstructed terminal evidence |
| deadline-action Store capability | `worldforge_ollama_deadline_action_store_capability_v1` | one invocation's two narrow Store methods |
| deadline-action capability registration | `worldforge_ollama_deadline_action_capability_registration_v1` | immutable pre-manager registration of one exact action capability |
| deadline credential source | `worldforge_ollama_deadline_credential_source_v1` | pending-before-create and ready exact encrypted-credential source custody |
| deadline credential file observation | `worldforge_ollama_deadline_credential_file_observation_v1` | exact created, fsynced and closed source identity used by the ready CAS |
| deadline-action load recipe | `worldforge_ollama_deadline_action_load_recipe_v1` | post-capability manager load request bound one-way to the ready credential source |
| deadline credential cleanup proof | `worldforge_ollama_deadline_credential_cleanup_proof_v1` | exact source closure, zeroization, inode unlink and parent-fsync proof |
| deadline-action static install | `worldforge_ollama_deadline_action_static_install_v1` | installed immutable helper/template prerequisite |
| timer clock observation | `worldforge_ollama_timer_clock_observation_v1` | bounded monotonic-to-boottime conversion |
| operation-effect timing | `worldforge_ollama_operation_effect_timing_v1` | same-clock disclosure/fork/listener/send ordering |
| manager-effect result | `worldforge_ollama_manager_effect_result_v1` | content-free PID1 request/reply/allocation observation |
| launch-lock projection | `worldforge_ollama_evidence_launch_lock_v1` | Studio-wide one-attempt launch exclusion and release generation |
| custody handoff chain | `worldforge_ollama_evidence_handoff_chain_v1` | durable ordered Acceptance chain head |
| private evidence artifact | `worldforge_ollama_private_evidence_artifact_v1` | non-executable content-free observed result projection |
| evidence limits | `worldforge_ollama_evidence_limits_v1` | single cross-layer operation/resource bound document |
| access policy | `worldforge_ollama_evidence_access_policy_v1` | all candidate-domain read, write, device and IPC rules |
| ambient sink catalog | `worldforge_ollama_ambient_sink_catalog_v1` | closed World Forge-observed host-sink queries |
| consumed-no-resources projection | `worldforge_ollama_evidence_consumed_no_resources_v1` | atomic one-use consumption and zero-resource state |
| opening projection | `worldforge_ollama_evidence_opening_v1` | registered operation-lease identity before creation |
| open projection | `worldforge_ollama_evidence_open_v1` | authenticated broker/candidate custody handoff |
| final-clean projection | `worldforge_ollama_evidence_final_clean_v1` | terminal evidence plus outer-scope cleanup proof |
| failed-clean projection | `worldforge_ollama_evidence_failed_clean_v1` | terminal failure plus outer-scope cleanup proof |
| failed-cleanup-pending projection | `worldforge_ollama_evidence_failed_cleanup_pending_v1` | immutable terminal attempt awaiting separate recovery |
| recovery projection | `worldforge_ollama_evidence_recovery_v1` | append-only pending/proven/failed cleanup recovery |
| systemd terminal projection | `worldforge_ollama_evidence_systemd_terminal_v1` | retained failed-unit result before reset/collection |
| cleanup proof | `worldforge_ollama_evidence_cleanup_proof_v1` | closed zero-resource, live-main or offline fixed point |
| device cleanup proof | `worldforge_ollama_evidence_device_cleanup_v1` | exact CPU-only/no-device closure |
| zero-allocation journal | `worldforge_ollama_evidence_zero_allocation_journal_v1` | pre-create absence across every resource class |
| manager-transaction rejection | `worldforge_ollama_manager_transaction_rejection_v1` | rejected create with exhaustive zero-allocation proof |
| boot-transition owner-death proof | `worldforge_ollama_boot_transition_owner_death_proof_v1` | authenticated old/new Linux boot fence |
| reboot-abort observation | `worldforge_ollama_reboot_abort_no_evidence_v1` | new-boot cleanup without old-runtime claims |
| HTTP wire-buffer observation | `worldforge_ollama_http_wire_buffer_observation_v1` | content-free hashes, bounds and zeroization proof for anonymous main-local buffers |
| native wire parser policy | `worldforge_ollama_native_wire_parser_policy_v1` | allocation-free, zero-copy parser implementation and output contract |
| native wire parser observation | `worldforge_ollama_native_wire_parser_observation_v1` | mapping census, bounded structural results and zero allocator/copy proof |
| protocol-text facet evidence | `worldforge_ollama_protocol_text_evidence_v1` | one non-stream text-success observation |
| pre-send-control facet evidence | `worldforge_ollama_control_pre_send_evidence_v1` | one zero-request-byte cancellation observation |
| post-send-control facet evidence | `worldforge_ollama_control_post_send_evidence_v1` | one timed disconnect observation |
| scenario evidence | `worldforge_ollama_scenario_evidence_v1` | one declared facet/scenario plan plus its observations |
| evidence envelope | `worldforge_ollama_evidence_envelope_v1` | one scenario evidence hash plus cleanup |
| evidence-eligibility abandonment | `worldforge_ollama_evidence_eligibility_abandonment_v1` | permanent pre-envelope reboot publication fence |
| private artifact payload | `worldforge_ollama_private_evidence_artifact_payload_v1` | deterministic content-free bytes rebuilt from durable projections |

This vocabulary contains exactly 86 rows and is exhaustive. A mechanical
registry check rejects a missing, duplicate, reordered or additional row and
requires every affirmatively declared top-level or embedded canonical `format`
literal in this ADR to resolve to exactly one row; explicitly forbidden aliases
are not registry entries. In particular, the custody transfer has exactly
the Offer and Acceptance format IDs above; there is no aggregate
`worldforge_ollama_evidence_custody_handoff_v1` format or alias.

Every **content or document** `*_hash` is lowercase SHA-256 over that exact
bounded canonical JSON document. The explicitly defined domain identifiers
`authorization_id`, `attempt_id`, `transaction_id`, `event_id`, `lease_id`,
`release_gate_id`, `capability_id`, `action_invocation_id`, `recovery_id` and
`endpoint_id`
instead hash their
named ASCII domain, NUL delimiters and exact ordered scalars. Fields explicitly
defined as file/blob/model/executable/library/ciphertext or other raw-byte
digests hash those exact bytes with SHA-256, never JSON. `nonce_hash`,
`release_gate_nonce_hash`, `lease_nonce_hash` and every `key_id` hash exact raw nonce/key bytes, not
JSON. Fields named exactly `authentication_hash` use HMAC-SHA256 over the named ASCII domain,
one NUL byte and the exact canonical bytes with only that field omitted. The
following exact formulas are the only additional hash-rule exceptions:

```text
recovery_fence_hash = SHA256(
  ASCII("worldforge-ollama-recovery-fence-document-v1") || 0x00 ||
  canonical_json(RecoveryFenceDocumentV1))
deadline_tombstone_key_hash = SHA256(
  ASCII("worldforge-ollama-deadline-tombstone-key-document-v1") || 0x00 ||
  canonical_json(DeadlineTombstoneKeyDocumentV1))
transition_target_body_hash = SHA256(
  ASCII("worldforge-ollama-transition-target-body-v1") || 0x00 ||
  canonical_json(StudioTransitionTargetBodyV1))
release_gate_id = SHA256(
  ASCII("worldforge-ollama-release-gate-id-v1") || 0x00 ||
  raw32(attempt_id) || 0x00 || raw32(authorization_hash) || 0x00 ||
  raw32(release_gate_nonce_hash) || 0x00 ||
  u64be(release_gate_id_generation) || 0x00 ||
  bool8(production_eligible) || 0x00)
lease_id = SHA256(
  ASCII("worldforge-ollama-operation-lease-id-v1") || 0x00 ||
  raw32(attempt_id) || 0x00 || raw32(authorization_hash) || 0x00 ||
  raw32(lease_nonce_hash) || 0x00 ||
  u64be(lease_id_generation) || 0x00 ||
  bool8(production_eligible) || 0x00)
capability_id = SHA256(
  ASCII("worldforge-ollama-deadline-action-capability-id-v1") || 0x00 ||
  raw32(attempt_id) || 0x00 || raw32(authorization_hash) || 0x00 ||
  raw32(operation_lease_hash) || 0x00 || u64be(execution_owner_epoch) || 0x00 ||
  raw32(release_gate_id) || 0x00 || u64be(deadline_boottime_ns) || 0x00 ||
  raw32(capability_nonce_hash) || 0x00)
action_invocation_id = SHA256(
  ASCII("worldforge-ollama-deadline-action-invocation-id-v1") || 0x00 ||
  raw32(attempt_id) || 0x00 || raw32(authorization_hash) || 0x00 ||
  raw32(operation_lease_hash) || 0x00 || u64be(execution_owner_epoch) || 0x00 ||
  raw32(release_gate_id) || 0x00 || raw32(action_recipe_hash) || 0x00 ||
  raw32(capability_nonce_hash) || 0x00)
authorization_id = SHA256(
  ASCII("worldforge-ollama-evidence-authorization-id-v1") || 0x00 ||
  decision_id || 0x00 || decimal(decision_generation) || 0x00 ||
  lowercase_hex(raw_32_byte_authorization_nonce))
recovery_id = SHA256(
  ASCII("worldforge-ollama-evidence-recovery-id-v1") || 0x00 ||
  attempt_id || 0x00 || authorization_hash || 0x00 ||
  lowercase_hex(raw_32_byte_recovery_nonce))
event_payload_hash = SHA256(
  ASCII("worldforge-ollama-studio-transition-event-payload-v1") || 0x00 ||
  canonical_json(StudioTransitionEventPayloadV1))
transaction_id = SHA256(
  ASCII("worldforge-ollama-studio-transaction-v1") || 0x00 ||
  attempt_id || 0x00 || decimal(transaction_revision) || 0x00 ||
  event_kind || 0x00 || prior_event_hash || 0x00 || transaction_request_hash)
event_id = SHA256(
  ASCII("worldforge-ollama-evidence-event-v1") || 0x00 ||
  attempt_id || 0x00 || decimal(transaction_revision) || 0x00 ||
  event_kind || 0x00 || event_payload_hash)
descriptor_198_record_hash = SHA256(
  ASCII("worldforge-ollama-descriptor-198-record-v1") || 0x00 ||
  Descriptor198RecordHeaderV1_bytes || payload_bytes)
```

For all fixed-width formulas, `raw32` is the exact 32 bytes decoded from a required
64-lowercase-hex scalar, and `u64be` is an unsigned eight-byte big-endian
integer. `bool8(false)` is exactly byte `0x00` and `bool8(true)` exactly byte
`0x01`; it is never ASCII or JSON. Every displayed `0x00` is one literal delimiter, including the one
after the last operand; there is no length prefix, JSON, lowercase-hex re-
encoding of a fixed-width operand or additional terminal byte.
For both release and lease IDs, generation is exactly one and
`production_eligible` exactly false. The raw 32-byte nonces are first hashed;
the formulas consume the decoded 32-byte nonce-hash values, not raw entropy or
their 64-byte hexadecimal text. Their final two bytes are therefore the false
boolean byte and the distinct terminal NUL. No lease/document/recipe, clock,
PID, owner or systemd value enters either ID.
The release/lease golden vector uses attempt bytes `00*32`, authorization bytes
`11*32`, release-nonce-hash bytes `22*32`, lease-nonce-hash bytes `33*32`,
generation one and false. The release domain is exactly 36 ASCII bytes; its
147-byte preimage hashes to
`508d3c1e2aa9104a8aec4a56d093fee195532c0000a913d515fc44ab17b4d4de`.
The lease domain is exactly 39 ASCII bytes; its 150-byte preimage hashes to
`d5c6344756bd08a49aebd123a4ef855fc8ab831a1cb6b39dbed3ca62c522c344`.
Any raw/hex swap, missing/interposed NUL, ASCII integer/boolean, generation
drift or extra terminal byte must fail these vectors.

The following stdlib-only fixture is the normative byte vector. Its two hex
strings are the complete preimages, including every delimiter and terminal
NUL; an implementation must execute these assertions rather than copy a digest:

```python
import hashlib

vectors = (
    (
        147,
        "776f726c64666f7267652d6f6c6c616d612d72656c656173652d676174652d69642d7631000000000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111002222222222222222222222222222222222222222222222222222222222222222000000000000000001000000",
        "508d3c1e2aa9104a8aec4a56d093fee195532c0000a913d515fc44ab17b4d4de",
    ),
    (
        150,
        "776f726c64666f7267652d6f6c6c616d612d6f7065726174696f6e2d6c656173652d69642d7631000000000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111003333333333333333333333333333333333333333333333333333333333333333000000000000000001000000",
        "d5c6344756bd08a49aebd123a4ef855fc8ab831a1cb6b39dbed3ca62c522c344",
    ),
)
for expected_size, preimage_hex, expected_digest in vectors:
    preimage = bytes.fromhex(preimage_hex)
    assert len(preimage) == expected_size
    assert hashlib.sha256(preimage).hexdigest() == expected_digest
```

`capability_nonce_hash` is `SHA256(raw_32_byte_capability_nonce)`. Both action IDs are
derived before any capability, registration, lifecycle, event or action-result
document and hash no consumer. The mandatory golden vector uses attempt bytes
`00*32`, authorization bytes `11*32`, lease bytes `22*32`, owner epoch `1`,
gate bytes `33*32`, deadline `600000000000` (big-endian
`0000008bb2c97000`), nonce-hash bytes `44*32`, and action-recipe bytes `55*32`.
Its 234-byte capability preimage hashes to
`3eeb658095abd10e7515d88abab69e50d44de8b01d243e9ebb6ee1d5e73c1124`;
its 258-byte action-invocation preimage hashes to
`2fb329073f1d03796c204584832ca343be671374ff21cf1c6513c1bff1170c21`.

The lowercase hexadecimal result is stored. No implementation may silently
canonicalize raw entropy, omit the domain/NUL byte, or replace a domain/HMAC
computation with an ordinary document hash.
For `authorization_id` and `recovery_id`, every `*_id`/`*_hash` operand is its exact
64-byte lowercase-ASCII hexadecimal encoding, `decision_generation` is its
minimal unsigned ASCII decimal encoding with no sign or leading zero, and each
raw nonce operand is first encoded as exactly 64 lowercase hexadecimal ASCII
bytes. `decision_id` is required to be a 64-lowercase-hex durable Director
decision identity. No Unicode normalization, JSON quoting, length prefix or
terminal NUL is added.

Hashes alone establish data integrity, never authority. Only the exact
root-issued, identity-registered authorization object can enter the one-use
consume flow. The exact release-gate snapshot, deadline-action Store capability
and handoff HMAC messages are short-lived, direction- and operation-bound
control authorities solely inside that already authorized evidence operation;
copies, persisted hashes and decoded lookalikes carry no authority. Every
evidence document, including an `observed_nonproduction` envelope, is
non-capability data and never a runtime binding, adapter, catalog, selection or
permission for a main-parent/provider turn.

Every ambient-service use and every implementation governed by this ADR has the
literal immutable value `production_eligible: false`. It cannot be supplied,
overridden or flipped by a caller or catalog constructor, and no production
catalog may admit it. Promotion requires a separate future versioned ADR and
fresh live evidence; passing this ADR's observation gates still cannot promote
it.

The closed availability values are `unavailable` and
`observed_nonproduction`; the current value is `unavailable`, and only an exact
evidence envelope that is internally complete for its declared scenario may be
labelled `observed_nonproduction`. Other closed values are
`pricing_status=unavailable`,
`egress_enforcement=not_enforced`,
`telemetry_status=observed_not_enforced`, and
`replay_support=not_claimed`. Only nonnegative prompt/evaluation counts actually
present in a bound provider response may be marked `observed`; cached-token
usage and monetary cost remain `unavailable`. No zero cost, currency or pricing
identity is invented. These values cannot be projected into current fields
whose semantics differ, and the candidate emits no public receipt.

`OllamaEvidenceLimitsV1` is the **only** numeric resource-limit authority. Its
exact ordered keys are `format`, `limits_generation`,
`maximum_operation_duration_ns`,
`outer_operation_process_identity_acceptance_max`,
`candidate_process_identity_acceptance_max`,
`runner_identity_acceptance_max`, `process_rlimit_nofile`,
`kernel_task_ceiling`,
`candidate_open_fd_acceptance_max`,
`candidate_socket_identity_acceptance_max`,
`candidate_local_ipc_entry_acceptance_max`,
`provider_request_wire_max_bytes`,
`provider_response_header_wire_max_bytes`,
`provider_response_wire_max_bytes`, `total_response_capture_max_bytes`,
`scratch_quota_bytes` and `scenario_scratch_acceptance_max_bytes`. `format` is
exactly `worldforge_ollama_evidence_limits_v1`; `limits_generation` is exactly
one; and the remaining values are, in that order, `600000000000`, `31`, `30`,
`29`, `4096`, `512`, `256`, `64`, `32`, `65536`, `65536`, `1048576`,
`16777216`, `268435456` and `67108864`. Every value is a built-in nonnegative integer no
larger than the JavaScript-safe maximum; bools, floats, aliases, unknown keys
and alternate units are rejected. Canonical JSON is at most 4,096 UTF-8 bytes
and `limits_hash` is its ordinary canonical-document hash.

The layers have distinct meanings. The three `*_process_identity_acceptance_max`
fields count exact retained PID/start identities in the evidence census; they
do not count threads and never configure systemd `TasksMax`. The distinct
`kernel_task_ceiling=512` configures systemd `TasksMax` and therefore bounds
the kernel task/cgroup PID count, including every thread and process. The 512
ceiling provides finite observed-only headroom for the server/runner's internal
CPU threads while the stricter 31/30/29 identity limits remain independently
enforced; it is not evidence that this candidate fits and cannot be raised by a
caller. `process_rlimit_nofile` is the configured
hard and soft `RLIMIT_NOFILE` ceiling inherited by service and runners;
`candidate_open_fd_acceptance_max` is the stricter per-process evidence-census
ceiling, so usable evidence requires
`observed_open_fds <= min(observed_soft_rlimit, observed_hard_rlimit, 4096,
256)`. `provider_response_wire_max_bytes` bounds one complete bounded in-memory
response wire image and `provider_response_header_wire_max_bytes` additionally
bounds its header block; all response bytes cumulatively received into the
anonymous main-local buffers across the scenario must additionally be at most
`total_response_capture_max_bytes`. No wire-buffer byte is file-backed. The
separate candidate operational scratch backing store is capped
at `scratch_quota_bytes`, while accepted scenario output is at most
`min(observed_quota_bytes, scratch_quota_bytes,
scenario_scratch_acceptance_max_bytes)`. Process, runner, socket, IPC, request
and operation-duration values apply only under their separately named fields;
none is reused as another layer's authority. The authorization, scenario plan
and scenario evidence, access policy, final candidate recipe, custody policy,
operation lease, transient-unit property snapshot and every relevant
configuration/result artifact all carry the same non-null `limits_hash`.
Any mismatch, absent reference, exceeded effective minimum or overflow makes
the scenario unusable and enters cleanup; a caller cannot relax a bound.

No result of this ADR permits a real user or project turn. A separate future
implementation ADR must define an executable catalog and selection, exact
disclosure approval, budgets, usage/pricing representation and accepted
telemetry risk before any `ProviderAdapter` or main-parent provider gateway may
exist. The synthetic GET-then-POST plan is never reused as Ollama protocol.
World Forge does not kill, restart, enable, disable or attach to the ambient
service/runner and makes no socket-activation claim.

### Exact local installation and model lock

The observed Linux/aarch64 static baseline is:

- `/etc/systemd/system/ollama.service`: `ExecStart=/usr/local/bin/ollama serve`,
  `User=ollama`, `Group=ollama`, `Restart=always`, `RestartSec=3`; its sole
  environment assignment is `PATH`. User/group IDs are 996/983. It declares no
  origin, model, model root or cloud policy; the binary's `127.0.0.1:11434`
  literal is not live listener evidence.
- `/usr/local/bin/ollama`: 35,789,064 bytes, SHA-256
  `213ca62ca17cda30e6ec1132cbb6d7fe4eee66b394eef6a3229d8b23f4b975a3`,
  Build ID `2e639fee54ccb2b540b389666ead45a7d4236153`, Go 1.26.0,
  Linux/ARM64/v8.0/CGO. Go provenance says `(devel)`; the embedded `~0.32.5`
  string is not release provenance and no package owns the binary.
- `/usr/bin/ollama` is a competing, rejected binary: 39,918,520 bytes,
  SHA-256 `259263d5ae0f8d716b9d8b199a137c9710ff348fa19dea0ce0120dc67735e171`,
  Build ID `bad9746095c525d063f8d586c58cac5d52763da2`, Go 1.24.1 `(devel)`.
- `/usr/local/lib/ollama/llama-server`: 68,384 bytes, SHA-256
  `f6e05586c5e7dd2110b2d8efadf23ff3b081dcdd53be67cfd32884af7b476163`,
  Build ID `b412ad96a72336aa54c43eef892b57d5250879ef`, `RUNPATH=$ORIGIN`.
  Its local `DT_NEEDED` closure is
  `libllama-server-impl.so=f93c016bc569e25f1815b055673fb6f0f9986eadd181b3741145e44c3126ce05`,
  `libllama-common.so.0=9b1829a3f11aec54dc033a09af23ed4528c692b8b5fe856b8605c61bf63e5b0e`,
  `libmtmd.so.0=608c2d5dfc53fc3af7489f7b0f45fd83c99496c4f3f1d7e9fcad9794cdada7b1`,
  `libllama.so.0=d5b22b1cabde550a862bb8de6fed52aa315a621cd48dcdf4fac40d6da46850eb`,
  `libggml.so.0=712fa491afd88753305eed4e2afd4054bc046ed726306f4faa049ca836125128`,
  and
  `libggml-base.so.0=c3aa630bae1d0446d34c856408c01f74b703438f5847804d665768b34c590c89`.
  Its resolved system closure includes `libpthread.so.0`, `libstdc++.so.6`,
  `libm.so.6`, `libgcc_s.so.1`, `libc.so.6`, transitive `libdl.so.2` and the
  AArch64 loader. The logical controller inventories the resolved paths/hashes
  and the exact CPU backend selected; the envelope binds that observation, not
  approval. Merely inventorying the eight ARM CPU variants and CUDA 12/13
  libraries does not prove runtime selection, and selecting any CUDA/device
  backend is V1 drift.

No path under this ADR installs, upgrades, pulls or downloads anything. The
candidate model lock is the 710-byte
`registry.ollama.ai/library/qwen3.6/27b` manifest, SHA-256
`a50eda8ed977ab48a12431878896b27ffd5cef552c17af3317d9623b939a7f1e`:

| Blob | SHA-256 | Bytes |
|---|---|---:|
| config | `728c795c776272002ed455cf94ef825cbbe4cc04c9a925a1a78933bbf0c2b63b` | 456 |
| model | `83c54730a5fea8a0958598c01617c1419c431e93b33bacf980b49a420c798926` | 17,420,420,832 |
| license | `5f3a3c817e78f5b8a4ad2d2c458a3e4b2cce470d6c12642c4eeb12cb8a9bf51d` | 11,357 |
| parameters | `86eff881e8d2c2b1caa3966ba775d007f76a693d8541d0973b1bd2aab4214a43` | 94 |

All four blob hashes were verified. The config declares `gguf`, family
`qwen35`, type `27.8B`, `Q4_K_M`, renderer/parser `qwen3.5`, and OCI
`amd64/linux`; these declarations do not establish host compatibility. The
model is GGUF v3 with 1,307 tensors, 53 metadata entries, architecture
`qwen35`, 27,781,427,952 parameters, file type 15, quantization version 2,
context 262,144, embedding 5,120, 64 blocks and 24 attention heads. Its GPT-2
tokenizer/pre-tokenizer is `qwen35`; the 7,764-byte chat template hashes to
`e84f32a23fdda27689f868aa4a1a5621f41133e51a48d7f3efcbea2839574259`.
The parameter blob is exactly
`{"min_p":0,"presence_penalty":1.5,"repeat_penalty":1,"temperature":1,"top_k":20,"top_p":0.95}`.
There is no `general.name` or `general.basename`. The local `qwen3.6:27b` tag,
these metadata, and an Apache-2.0 text layer do not authenticate an upstream
marketing identity or establish weight, dataset or output licensing.

### Canonical installation, lock, plan and evidence schemas

The authorities named in the vocabulary are closed byte contracts, not prose
aliases. In this section `u53` means a built-in JSON integer in
`0..9007199254740991`, `pos53` means `1..9007199254740991`, `hex64` means
exactly 64 lowercase hexadecimal ASCII characters, `utc35` means a canonical
UTC timestamp of at most 35 ASCII bytes, and `path4096` means an absolute,
normalized UTF-8 realpath of at most 4,096 bytes. Unless a smaller bound is
stated, strings are at most 4,096 UTF-8 bytes, arrays are ordered and at most
128 entries, and a document is at most 524,288 canonical UTF-8 bytes. Every
listed key is mandatory in the listed order, including nullable keys; unknown,
duplicate, missing or reordered keys, bool-as-int, floats and non-built-in
scalars are rejected.

The shared embedded `ExactFileIdentityV1` has exactly `realpath:path4096`,
`device:u53`, `inode:u53`, `mode:u53`, `uid:u53`, `gid:u53`, `size:u53`,
`sha256:hex64` and nullable `build_id` (lowercase hex, 8..128 characters).
`InstallationFileEntryV1` has exactly `role`, `file`, `file_kind`,
`architecture`, nullable `go_version`, nullable `module_path`, nullable
`module_version`, `needed`, nullable `runpath`, and `provenance_class`.
`file` is `ExactFileIdentityV1`; role is one of `server_v1`,
`competing_server_v1`, `runner_v1`, `runner_library_v1`,
`system_library_v1`, `cpu_backend_candidate_v1` or
`accelerator_backend_inventory_only_v1`; kind is `elf_pie_v1`,
`elf_executable_v1` or `elf_shared_object_v1`; architecture is exact ASCII;
`needed` is a duplicate-free ordered array of at most 64 ASCII sonames; and
provenance is only `hash_build_id_proven_v1`, `devel_module_only_v1` or
`inventory_only_v1`. `StaticFactV1` has exactly `fact_kind`,
`subject_file_sha256:hex64`, nullable `byte_offset:u53`,
`literal_bytes_sha256:hex64`, and `claim_limit`; its closed kinds are
`loopback_literal_v1`, `cloud_knob_literal_v1`, `cloud_route_literal_v1`,
`http_route_disassembly_v1` and `json_tag_literal_v1`; claim limit is only
`literal_presence_only_v1` or `route_registration_static_only_v1`.

`OllamaInstallationObservationV1` has exactly, in order: `format`,
`observation_generation`, `platform_os`, `platform_architecture`,
`linux_boot_id`, `ambient_unit_file`, `ambient_exec_argv`, `ambient_user`,
`ambient_group`, `ambient_restart_policy`, `ambient_restart_sec`,
`ambient_environment`, nullable `ambient_explicit_host`, nullable
`ambient_explicit_model_root`, nullable `ambient_explicit_no_cloud`,
`account_name`, `group_name`, `account_uid`, `account_gid`, `account_home`,
`account_shell`, `expected_groups`, `file_entries`, `static_facts`,
`observation_tool_hash`, `provenance_limitations`, and `observed_at`.
`format` is exactly `worldforge_ollama_installation_observation_v1`, generation
is one, OS/architecture are `linux`/`aarch64`, boot ID is the canonical Linux
UUID, `ambient_unit_file` is `ExactFileIdentityV1`, argv is a 1..64 string
array, environment is a duplicate-free ordered array of exact `{name,value}`
string objects, expected groups is an ordered duplicate-free `u53` array,
account home/shell are `path4096`, user/group names are nonempty ASCII and
UID/GID/restart seconds are `u53`;
restart policy is `always`, the three explicit ambient values are null for this
baseline, file entries are 3..128 exact entries above with unique paths and
unique `(role,path)` pairs,
static facts are 1..128 exact entries, tool hash is an ordinary content-document
hash, limitations is a 1..32 array of nonempty strings, and time is `utc35`.
Each embedded file/literal SHA is a raw-byte digest; `observation_tool_hash` is
the sole content reference. The current observation must encode the exact unit,
account, binary, runner and closure facts pinned above, including the competing
binary and `(devel)` limitation; it cannot infer a semantic release, live bind,
selected backend or service origin.

The embedded `OllamaModelLayerV1` has exactly `ordinal:u53`, `media_type`,
`role`, `digest:hex64`, `size:u53`, `blob_file:ExactFileIdentityV1` and
`bytes_verified`; ordinals are contiguous, roles are exactly `config`, `model`,
`license`, `parameters` in that order, and `bytes_verified=true`.
`OllamaGGUFMetadataV1` has exactly `version`, `tensor_count`, `metadata_count`,
`architecture`, `parameter_count`, `file_type`, `quantization_version`,
`context_length`, `embedding_length`, `block_count`, `attention_head_count`,
`tokenizer_model`, `tokenizer_pre`, `chat_template_size`,
`chat_template_sha256`, nullable `general_name`, and nullable
`general_basename`; every count is `u53`, the two names are null here, and the
template hash is a raw-byte digest.

`OllamaModelLockV1` has exactly `format`, `lock_generation`, `local_tag`,
`manifest_file`, `manifest_digest`, `manifest_size`, `layers`,
`config_model_format`, `config_family`, `config_families`,
`config_model_type`, `config_file_type`, `config_renderer`, `config_parser`,
`config_oci_architecture`, `config_oci_os`, `gguf_metadata`,
`parameters_json_sha256`, `license_text_class`, `identity_class`,
`provenance_limitations`, and `locked_at`. Format is exactly
`worldforge_ollama_model_lock_v1`, generation is one, `manifest_file` is
`ExactFileIdentityV1`, its digest/size equal that nested identity, `layers` is
the exact four-entry array above, `config_families` is a nonempty ordered ASCII
array, metadata is the exact object above, parameter/manifest hashes are raw
byte digests, license class is `apache_2_0_text_observed_v1`, and identity class
is `local_tag_qwen35_bytes_unattributed_v1`. The remaining strings and numbers
must equal the pinned values above. The lock contains no marketing/upstream
identity assertion.

The four construction-time policy documents are complete as follows:

- `OllamaEvidenceControllerPlanV1` has exactly `format`, `plan_generation`,
  `production_eligible`, `controller_principal`, `controller_process_model`,
  `scenario_catalog_hash`, `fixed_request_catalog_hash`,
  `installation_observation_hash`, `model_lock_hash`,
  `candidate_profile_hash`, `candidate_recipe_policy_hash`,
  `access_policy_hash`, `custody_policy_hash`, `operation_lease_policy_hash`,
  `systemd_policy_hash`, `descriptor_198_registry_hash`,
  `native_wire_parser_policy_hash`, `limits_hash`,
  `authorized_effects`, `caller_input_allowed`, `project_data_allowed`,
  `provider_adapter_allowed`, `retry_allowed`, `result_projection`, and
  `maximum_document_bytes`. Format is
  `worldforge_ollama_evidence_controller_plan_v1`, generation is one,
  production and all four permission/retry booleans are false, principal/model
  are `studio_main_ollama_controller_v1` and `main_logical_authority_v1`, effects
  are exactly `[config_disclosure,fork_exec,listener_effect,request_send]`,
  result projection is `private_nonexecutable_v1`, and the positive byte limit
  is at most 524,288.
- `OllamaEvidenceScenarioPlanV1` has exactly `format`, `plan_generation`,
  `facet_id`, `scenario_id`, `facet_artifact_format`, `controller_plan_hash`,
  `fixed_request_bytes_hash`, `http_method`, `http_path`, `stream`,
  `cancellation_phase`, nullable `disconnect_after_ns`, `response_mode`,
  `access_policy_hash`, `candidate_profile_hash`, `candidate_recipe_policy_hash`,
  `custody_policy_hash`, `operation_lease_policy_hash`, `limits_hash`,
  `caller_payload_allowed`, `project_data_allowed`, `retry_allowed`, and
  `plan_maximum_bytes`. Format is `worldforge_ollama_evidence_scenario_plan_v1`,
  generation is one, the facet/scenario/artifact triple is exactly one catalog
  row below, method/path are `POST` and `/api/chat`, stream and the three
  permission/retry booleans are false. Cancellation is only `none_v1`,
  `before_first_request_byte_v1`, or `one_second_after_runner_observed_v1`;
  disconnect is exactly 1,000,000,000 only for the latter and null otherwise;
  response mode is `one_terminal_nonstream_v1`, `no_response_v1`, or
  `disconnect_without_terminal_acceptance_v1` respectively.
  `plan_maximum_bytes` is the exact positive-JavaScript-safe integer `524288`,
  and the complete canonical scenario-plan byte length must be less than or
  equal to that value. A plan whose canonical representation is larger is
  invalid before authorization; the field is not caller-adjustable.
- `OllamaEvidenceSystemdPolicyV1` has exactly `format`, `policy_generation`,
  `manager_scope`, `manager_peer_policy_hash`, `operation_unit_type`,
  `operation_user`, `operation_group`, `supplementary_groups`, `dynamic_user`,
  `no_new_privileges`, `ambient_capabilities`, `capability_bounding_set`,
  `device_policy`, `device_allow_entries`, `kill_mode`, `collect_mode`,
  `restart_policy`, `standard_input`, `standard_input_fd_property`,
  `start_transient_signature`, `load_unit_signature`, `ref_unit_signature`,
  `unref_unit_signature`, `operation_auxiliary_units`,
  `timer_retention_relation`, `timer_wake_system`,
  `timer_randomized_delay_usec`, `timer_remain_after_elapse`,
  `deadline_action_static_install_policy_hash`,
  `terminal_retention_policy_hash`, `manager_reply_journal_policy_hash`,
  and `limits_hash`. Format is `worldforge_ollama_evidence_systemd_policy_v1`,
  generation one; `manager_scope` is exactly `system_pid1_v1`; the remaining
  exact values are `exec`, `ollama`, `ollama`,
  empty groups, false/true/zero/zero, `closed`, empty DeviceAllow,
  `control-group`, `inactive`, `no`, `fd`,
  `StandardInputFileDescriptor`, `ssa(sv)a(sa(sv))`, `s->o`, `s->()`,
  `s->()`, empty auxiliary array, `Requisite+After`, true, zero and true in the
  listed order. All `*_hash` fields are ordinary content references.
- `OllamaOperationLeasePolicyV1` has exactly `format`, `policy_generation`,
  `mechanism`, `systemd_policy_hash`, `lease_id_domain`, `operation_unit_domain`,
  `timer_unit_domain`, `action_template_name`, `clock_domain`,
  `deadline_formula`, `manager_idempotency_policy_hash`,
  `main_loss_lease_policy_hash`, `candidate_subgroup_policy_hash`,
  `cleanup_policy_hash`, `allowed_cleanup_modes`, `limits_hash`, and
  `execution_available`. Format is `worldforge_ollama_operation_lease_policy_v1`,
  generation one, mechanism/clock are
  `systemd_pid1_transient_operation_service_v1`/`linux_clock_boottime_v1`;
  the five values are exactly `worldforge-ollama-operation-lease-v1`,
  `worldforge-ollama-evidence-{lease_id}.service`,
  `worldforge-ollama-evidence-deadline@{lease_id}.timer`,
  `worldforge-ollama-evidence-deadline@.service`, and
  `opened_boottime_ns+LimitsV1.maximum_operation_duration_ns`; cleanup modes
  equal the exact access-policy array, and
  `execution_available=false`.

The dynamic recipe hashes used by those policies are equally closed.
`OllamaSystemdUnitRecipeV1` has exactly `format`, `recipe_kind`, `attempt_id`,
`authorization_hash`, `custody_policy_hash`, `operation_lease_policy_hash`,
`systemd_policy_hash`,
`execution_owner_epoch`, `linux_boot_id`, `lease_id`, `unit_name`,
`unit_object_path`, nullable `deadline_action_static_install_hash`,
`property_entries`, `dbus_method`, `dbus_signature`,
`auxiliary_unit_names`, `limits_hash`, and `derived_at`. Format is
`worldforge_ollama_systemd_unit_recipe_v1`; kind is exactly
`outer_operation_service_v1`, `deadline_timer_v1` or
`static_deadline_action_instance_v1`; properties are a 0..128 ordered array of
exact `{name,variant_signature,value}` objects with no duplicate; method/signature
are the exact PID1 method pair for that kind. Outer/timer recipes require the
install hash null and their property entries equal the kind-specific systemd
policy projection byte-for-byte. The static action is not transient: its recipe
requires the exact non-null static-install hash, an empty `property_entries`
array, `dbus_method=LoadUnit`, `dbus_signature=s->o`, and obtains its property
snapshot solely by reading and hashing the installed unit-file/helper contract.
Auxiliary names are empty and unit name/path derive from the lease.
`OllamaNativeProcessRecipeV1` has exactly
`format`, `attempt_id`, `authorization_hash`, `custody_policy_hash`,
`lease_id`, `broker_recipe_policy_hash`, `process_kind`, `executable_file`,
`argv`, `environment`,
`credential_policy_hash`, `native_single_thread_broker_policy_hash`,
`stdin_fd_policy_hash`, `ready_policy_hash`, `limits_hash`, and
`recipe_generation`; format/kind are
`worldforge_ollama_native_process_recipe_v1`/`evidence_broker_v1`, file is
`ExactFileIdentityV1`, argv is a 1..64 string array, environment is a 0..64
ordered array of exact unique `{name,value}` string objects, and
generation is one. `OllamaCandidateSubgroupRecipeV1` has exactly `format`,
`attempt_id`, `authorization_hash`, `custody_policy_hash`,
`operation_lease_policy_hash`, `systemd_policy_hash`, `lease_id`,
`outer_unit_name`, `subgroup_name`, `subgroup_identity_policy_hash`,
`process_acceptance_max`, `runner_acceptance_max`, `device_policy`,
`device_allow_entries`, `kill_authority_policy_hash`, `limits_hash`, and
`derived_at`; format is `worldforge_ollama_candidate_subgroup_recipe_v1`,
device policy/allow are `closed`/empty, and counts equal LimitsV1. Every dynamic
recipe is derived only after authorization and lease-ID registration, binds
those scalars plus the static derivation policy, and contains no operation-lease
document hash. Attempt and
lease IDs are independent domain IDs, executable/file hashes are raw, and all
other hashes are backward ordinary content references. `broker_recipe_hash`,
`outer_unit_recipe_hash`, `deadline_timer_recipe_hash`,
`deadline_action_recipe_hash` and `candidate_subgroup_recipe_hash` may name only
the matching document/kind above; no prose-only recipe hash is valid.
The prelease static-action recipe binds only the static-install credential
directive/policy. It cannot contain an actual credential-source hash. The
separate post-capability load recipe is the sole manager recipe that binds the
completed ready source one-way and is deliberately outside OperationLease.

The two transient recipe kinds have complete, closed systemd D-Bus property
arrays. Each row below is one `a(sv)` entry in the displayed order; angle-
bracketed values are recipe scalars whose exact bytes/hash are already bound by
that recipe, not caller inputs. The outer operation service array is exactly:

| # | property | variant | exact value |
|---:|---|---|---|
| 0 | `Description` | `s` | `World Forge Ollama evidence <lease_id>` |
| 1 | `Type` | `s` | `exec` |
| 2 | `ExitType` | `s` | `main` |
| 3 | `ExecStart` | `a(sasb)` | `[(<broker_executable_realpath>,<exact_broker_argv>,false)]` |
| 4 | `User` | `s` | `ollama` |
| 5 | `Group` | `s` | `ollama` |
| 6 | `SupplementaryGroups` | `as` | `[]` |
| 7 | `DynamicUser` | `b` | `false` |
| 8 | `NoNewPrivileges` | `b` | `true` |
| 9 | `AmbientCapabilities` | `t` | `0` |
| 10 | `CapabilityBoundingSet` | `t` | `0` |
| 11 | `DevicePolicy` | `s` | `closed` |
| 12 | `DeviceAllow` | `a(ss)` | `[]` |
| 13 | `KillMode` | `s` | `control-group` |
| 14 | `SendSIGKILL` | `b` | `true` |
| 15 | `Restart` | `s` | `no` |
| 16 | `RemainAfterExit` | `b` | `false` |
| 17 | `CollectMode` | `s` | `inactive` |
| 18 | `SuccessExitStatus` | `(aiai)` | `([],[])` |
| 19 | `Delegate` | `b` | `true` |
| 20 | `TasksMax` | `t` | `512` |
| 21 | `LimitNOFILE` | `t` | `4096` |
| 22 | `LimitNOFILESoft` | `t` | `4096` |
| 23 | `RuntimeMaxUSec` | `t` | `<derived_runtime_max_usec>` |
| 24 | `TimeoutStopUSec` | `t` | `60000000` |
| 25 | `StandardInput` | `s` | `fd` |
| 26 | `StandardInputFileDescriptor` | `h` | `<broker_endpoint_unix_fd_index>` |
| 27 | `StandardOutput` | `s` | `file:<owned_stdout_capture_realpath>` |
| 28 | `StandardError` | `s` | `file:<owned_stderr_capture_realpath>` |
| 29 | `SetCredentialEncrypted` | `a(say)` | `[("worldforge.broker-ready-key-v1",<exact_encrypted_ready_key_bytes>)]` |

`derived_runtime_max_usec` is the checked defense-only value defined below;
both capture paths are exact entries in the access policy and their complete
strings are part of the recipe. The empty success-status tuple intentionally
keeps sentinels 124, 125 and 126 non-success. There is no omitted/defaulted
property that may override a row, no duplicate entry, and the auxiliary-unit
array is exactly empty.

The deadline timer array is exactly:

| # | property | variant | exact value |
|---:|---|---|---|
| 0 | `Description` | `s` | `World Forge Ollama evidence deadline <lease_id>` |
| 1 | `OnBootUSec` | `t` | `<timer_on_boot_usec>` |
| 2 | `AccuracyUSec` | `t` | `<timer_accuracy_usec>` |
| 3 | `RandomizedDelayUSec` | `t` | `0` |
| 4 | `WakeSystem` | `b` | `true` |
| 5 | `RemainAfterElapse` | `b` | `true` |
| 6 | `Persistent` | `b` | `false` |
| 7 | `Requisite` | `as` | `[<outer_operation_unit_name>]` |
| 8 | `After` | `as` | `[<outer_operation_unit_name>]` |
| 9 | `CollectMode` | `s` | `inactive` |

It deliberately has no `Unit` entry: local systemd 255 transient-settings
documentation does not support transient `Unit=` for timer creation. The
deterministic timer name is instead
`worldforge-ollama-evidence-deadline@<lease_id>.timer`, so systemd's exact
same-basename timer target is the already installed and attested static
`worldforge-ollama-evidence-deadline@<lease_id>.service`. That static action is
defined only by the immutable unit-file/helper bytes in
`OllamaDeadlineActionStaticInstallV1`, loaded with `LoadUnit(s)->o`; it is not a
third transient array, auxiliary definition or socket-activated service.

This is a proposed byte contract, not local conformance evidence. The same
systemd 255 documentation lists `StandardInput=` but does **not** list an input
property named `StandardInputFileDescriptor`; its D-Bus interface exposes only
the string observation property `StandardInputFileDescriptorName`, which does
not accept or identify an attached UNIX_FD. Therefore row 26 and the resulting
fd-0 delivery semantics remain specifically unproven. No caller, fallback,
descriptor name or stdin inheritance may substitute. Construction and
execution remain unavailable until a sacrificial non-provider live test proves
the exact `h` property, method bytes, received fd and retained snapshot on the
pinned systemd build; rejection or absence keeps the ADR unavailable.

For those four documents, every named `*_hash` is an ordinary already-complete
content-document reference except `fixed_request_bytes_hash`, which is the raw
fixed request digest; strings/arrays/booleans are scalar policy data. They
contain no attempt, lease, final recipe, event, target-body, live process or
evidence-envelope hash. The existing `controller_plan_hash`,
`scenario_plan_hash`, `systemd_policy_hash` and
`operation_lease_policy_hash` fields may name only these respective documents.

`OllamaCandidateRecipePolicyV1` is also fully typed: its exact key order is the
one published below, all eight `*_hash` fields are nonzero ordinary content
references to completed static policy/profile documents, `policy_generation`
is exactly one, the canonical document is at most 4,096 bytes, and it contains
no nullable field, operation identity or final recipe hash.

The three facet artifacts are closed:

- `OllamaProtocolTextEvidenceV1` has exactly `format`, `attempt_id`,
  `authorization_hash`, `scenario_plan_hash`, `request_bytes_hash`,
  `request_wire_hash`, `request_send_effect_timing_hash`,
  `peer_observation_hash`, `response_status`, `response_headers_hash`,
  `response_framing`, `response_body_hash`, `response_terminal_branch`,
  `prompt_eval_count_status`, nullable `prompt_eval_count`,
  `eval_count_status`, nullable `eval_count`, `close_observation_hash`,
  `capture_loss_count`, `result`, and `observed_at`. Format is
  `worldforge_ollama_protocol_text_evidence_v1`; status is `100..599`, framing
  is only `single_json_document_v1`, `newline_delimited_json_v1` or
  `other_bounded_unclassified_v1` (the last cannot be a success), terminal branch is
  `done_true_v1` or `error_terminal_v1`, count status is `observed` or
  `unavailable` with a `u53` value iff observed, loss is zero, and result is
  `success_observed_v1` or `scenario_unusable_v1`.
  `success_observed_v1` is valid **if and only if** the exact request above was
  sent once in full and all of these closed predicates hold: one final
  `HTTP/1.1 200` response and no informational response; exactly one
  `Content-Type` value after ASCII case-insensitive field-name matching whose
  OWS-trimmed ASCII bytes are `application/json`, with no obs-fold;
  exactly one canonical unsigned-decimal `Content-Length` equal to the captured
  body length; exactly one OWS-trimmed `Connection` value `close`; no
  `Transfer-Encoding` or `Content-Encoding`; response framing
  `single_json_document_v1`; one UTF-8 JSON object parsed with duplicate-key
  rejection; its member-name set is a subset of exactly `model`, `created_at`,
  `message`, `done`, `done_reason`, `total_duration`, `load_duration`,
  `prompt_eval_count`, `prompt_eval_duration`, `eval_count` and
  `eval_duration`; top-level `done` is the JSON literal `true`; top-level
  `error` is absent; `message` has exactly the two members `role` and `content`,
  with `role` exactly `assistant` and `content` UTF-8 bytes exactly
  `WORLD_FORGE_OLLAMA_EVIDENCE_V1`, with no prefix, suffix or whitespace;
  `thinking`, images, tool calls, tool name, tool-call ID and every other
  semantic-output carrier are absent; if present, `model` is exactly
  `qwen3.6:27b`, `created_at` is a nonempty string of at most 128 UTF-8 bytes,
  `done_reason` is exactly `stop`, and every duration/count value is a `u53`;
  terminal branch is
  `done_true_v1`; captured header/body/request byte counts equal their declared
  values and stay within `LimitsV1`; `capture_loss_count=0`; and after exactly
  the declared body the peer produces a clean EOF with no trailing byte before
  the response deadline. Usage-count fields may be observed only from the same
  object under their rules above and are not part of semantic token equality.
  Any other status/version, interim response, missing/duplicate/conflicting
  header, chunking/compression, malformed/duplicate-key/trailing JSON, `error`
  presence, `done!=true`, semantic-token mismatch, extra semantic output,
  partial/extra/lost byte, timeout, reset or unclean close deterministically
  sets `result=scenario_unusable_v1`; no combination with such a condition can
  be labelled success. This predicate accepts one probe observation only and
  makes no claim about any unexercised vendor protocol branch.
- `OllamaControlPreSendEvidenceV1` has exactly `format`, `attempt_id`,
  `authorization_hash`, `scenario_plan_hash`, `operation_effect_timing_set_hash`,
  `peer_observation_hash`, `connected_socket_identity_hash`,
  `cancellation_admission_hash`, `request_bytes_observed`,
  `request_send_timing_hash`, `socket_close_observation_hash`,
  `domain_cleanup_proof_hash`, `capture_loss_count`, `effect_classification`,
  `result`, and `observed_at`. Format is
  `worldforge_ollama_control_pre_send_evidence_v1`; request bytes/loss are zero,
  send timing is exact `no_effect`, classification/result are
  `clean_before_send`/`clean_before_send_observed_v1` or the whole artifact is
  `scenario_unusable_v1` and cannot enter an envelope.
- `OllamaControlPostSendEvidenceV1` has exactly `format`, `attempt_id`,
  `authorization_hash`, `scenario_plan_hash`, `request_bytes_hash`,
  `request_wire_hash`, `request_send_effect_timing_hash`,
  `exact_runner_state_hash`, `disconnect_after_ns`,
  `socket_close_observation_hash`, `subsequent_transition_set_hash`,
  `domain_cleanup_proof_hash`, `capture_loss_count`, `effect_classification`,
  `provider_cancellation_claimed`, `result`, and `observed_at`. Format is
  `worldforge_ollama_control_post_send_evidence_v1`; disconnect is exactly
  1,000,000,000, loss is zero, classification is
  `indeterminate_after_possible_send`, cancellation claimed is false, and
  result is `disconnect_observed_without_cancellation_claim_v1` or
  `scenario_unusable_v1`.

For all facets, `attempt_id` is an independent domain ID; request, wire,
headers and body hashes are raw-byte digests; authorization, scenario plan,
effect timing, peer/socket/runner/transition/close and cleanup hashes are
already-complete content references. They contain no raw prompt, response or
log bytes.

The static `OllamaNativeWireParserPolicyV1` has exactly `format`,
`policy_generation`, `parser_executable_hash`, `parser_build_id_hash`,
`parser_library_closure_hash`, `parser_entrypoint_hash`, `parser_abi_hash`,
`input_role_order`, `allowed_output_kinds`, `fixed_token_bytes_hash`,
`dynamic_allocation_allowed`, `raw_copy_out_allowed`,
`ordinary_heap_raw_bytes_allowed`, `raw_text_materialization_allowed`,
`syscall_policy_hash`, `mapping_census_policy_hash`, `limits_hash` and
`execution_available`. `format` is exactly
`worldforge_ollama_native_wire_parser_policy_v1`; generation is one; input
roles are exactly `[request_wire_mapping_v1,response_wire_mapping_v1]`; output
kinds are exactly `[offset_range_v1,raw_bytes_sha256_v1,u53_numeric_value_v1,presence_bit_v1,fixed_token_equal_v1,protocol_enum_v1]`;
the four permission booleans and `execution_available` are false; and
`fixed_token_bytes_hash` is the raw SHA-256 of
`WORLD_FORGE_OLLAMA_EVIDENCE_V1`. All remaining hashes name exact pinned native
code/ABI/closure, a closed no-I/O parser syscall policy, the full mapping-census
algorithm and the one shared Limits document. It contains no final recipe,
attempt, mapping address or provider bytes.

The parser is fixed native code, single-threaded, allocation-free and
zero-copy. It reads only the two already locked controlled mappings by bounded
offset; maintains SHA-256 state and its fixed-size result structure on the
native stack; and emits only offsets, raw-byte hashes, checked numeric counts,
presence bits, protocol enums and the exact-token equality bit. Header names,
header values, JSON strings and provider text are compared in place and are
never materialized in an ordinary heap, Python object, copied string or third
buffer. Its `OllamaNativeWireParserObservationV1` has exactly `format`,
`attempt_id`, `authorization_hash`, `scenario_plan_hash`,
`native_wire_parser_policy_hash`, `limits_hash`,
`request_mapping_observation_hash`, `response_mapping_observation_hash`,
`mapping_census_before_hash`, `mapping_census_after_hash`,
`offset_range_set_hash`, `raw_bytes_hash_set_hash`,
`numeric_value_set_hash`, `presence_bit_set_hash`,
`protocol_enum_set_hash`, `fixed_token_equal`, `allocator_call_count`,
`raw_copy_out_byte_count`, `ordinary_heap_raw_byte_count`,
`raw_text_materialization_count`, `syscall_observation_hash`,
`observation_loss_count`, `result_class` and `observed_at`. `format` is exactly
`worldforge_ollama_native_wire_parser_observation_v1`; the four counts and loss
count are zero; `fixed_token_equal` is a boolean; and `result_class` is only
`bounded_zero_copy_observed_v1` or `scenario_unusable_v1`. The two censuses are
full-process VMA, `/proc/self/maps`, `/proc/self/smaps`, locked-page and
ownership observations, not samples of only the two wire mappings. They must
be byte-identical except for the exact two wire VMAs' expected accessed/dirty
accounting and must show no new mapping, allocator, copy target, fd, thread or
syscall authority. Every set hash names a bounded content-free ordered
observation, never raw text. Missing native bytes, an
allocator/copy/census hook gap or any nonzero count makes the scenario
unusable. No such native parser or live proof exists on this host, so execution
remains unavailable.

The main-process logical controller uses exactly one
`OllamaHttpWireBufferV1` request mapping and one response mapping. Each is a
private anonymous mapping created with `MAP_PRIVATE|MAP_ANONYMOUS`; the
application creates no path, file descriptor, memfd, shared-memory name or
file backing for either mapping. Before any wire byte enters, native code
applies `MADV_DONTDUMP|MADV_DONTFORK`, reads the exact soft/hard
`RLIMIT_MEMLOCK`, proves the page-rounded combined mapping length is within
both limits and successfully `mlock`s both complete mappings. Failure of any
step makes the scenario unusable before disclosure. Request capacity is
exactly `LimitsV1.provider_request_wire_max_bytes`; response capacity is
exactly `LimitsV1.provider_response_wire_max_bytes`; used counts and the
cumulative response counter must also satisfy every applicable `LimitsV1`
bound. Only the code-owned HTTP encoder, native parser and exact connected
socket authority can access these mappings. A complete native maps/smaps/
locked-page census runs before parse and again before teardown.

After raw digests and bounded structural observations are frozen, the native
controller performs `explicit_bzero` over both complete page-rounded mappings,
proves every byte zero, calls `munlock`, applies `MADV_DONTNEED`, unmaps both
mappings and seals the teardown census before ScenarioEvidence. No byte is
copied to a file, scratch path, log, Store, descriptor 198, artifact or receipt,
and no raw replay/transcript is retained. The only accepted memory claim is
that the application created no file backing and the successfully locked pages
were not eligible for swap while locked. Hibernation, host/kernel crash capture,
core-dump mechanisms outside `MADV_DONTDUMP`, hypervisor/firmware capture and
other undeclared host memory sinks remain residual risks unless a future
profile separately disables and proves them; this ADR never claims absolute
absence of persistent backing.

The resulting content-free `OllamaHttpWireBufferObservationV1` has exactly
`format`, `attempt_id`, `authorization_hash`, `scenario_plan_hash`,
`limits_hash`, `request_mapping_observation_hash`,
`response_mapping_observation_hash`, `request_capacity_bytes`,
`request_used_bytes`, `response_capacity_bytes`, `response_used_bytes`,
`total_response_received_bytes`, `mapping_kind`, `mapping_flags`,
`madvise_flags`, `page_size_bytes`, `request_mapping_length_bytes`,
`response_mapping_length_bytes`, `observed_rlimit_memlock_soft_bytes`,
`observed_rlimit_memlock_hard_bytes`, `mlock_observation_hash`,
`locked_page_census_before_hash`, `locked_page_census_after_hash`,
`backing_fd_count`, `backing_path_present`,
`application_file_backing_created`, `swap_while_locked_claimed`,
`absolute_persistence_absence_claimed`,
`request_wire_sha256`, `response_wire_sha256`, nullable
`structured_parse_observation_hash`, `zeroization_observation_hash`,
`munlock_observation_hash`, `unmap_observation_hash`,
`memory_protection_result`, `memory_protection_failures`,
`residual_host_risks`, `raw_bytes_retained` and `observed_at`. `format` is exactly
`worldforge_ollama_http_wire_buffer_observation_v1`; `mapping_kind` is
`anonymous_private_v1`; the ordered flag arrays are exactly
`[MAP_PRIVATE,MAP_ANONYMOUS]` and `[MADV_DONTDUMP,MADV_DONTFORK]`;
`backing_fd_count=0`, `backing_path_present=false`,
`application_file_backing_created=false`, `swap_while_locked_claimed=true`,
`absolute_persistence_absence_claimed=false` and `raw_bytes_retained=false`.
`page_size_bytes` is the exact positive observed page size; each mapping length
is the checked page-size round-up of its capacity; both observed memlock limits
are at least their checked sum; and the mlock plus both locked-page censuses
must prove every page locked continuously from before first byte through the
post-parse census. Counts are nonnegative `u53` values bounded by the
exact capacities/total limit; both `*_wire_sha256` values hash the exact used
bytes, including SHA-256 of empty bytes when used count is zero. The mapping
and teardown hashes name complete content-free native observation documents;
the parse hash is null only when the scenario performs no parse. Accepted
evidence requires `memory_protection_result=locked_zeroized_unmapped_v1`, an
exact empty `memory_protection_failures` array and `residual_host_risks`
exactly `[host_hibernation_uncontrolled_v1,host_crash_capture_uncontrolled_v1,external_host_memory_capture_uncontrolled_v1]`.
Any setup/lock/census/zeroization/munlock/unmap failure uses
`memory_protection_result=scenario_unusable_v1`, records closed content-free
failure codes and cannot create ScenarioEvidence. The only failure literals,
in occurrence order without duplicates, are
`page_size_unavailable_v1`, `mapping_length_overflow_v1`,
`rlimit_memlock_unavailable_v1`, `rlimit_memlock_insufficient_v1`,
`madvise_dontdump_failed_v1`, `madvise_dontfork_failed_v1`,
`request_mlock_failed_v1`, `response_mlock_failed_v1`,
`locked_page_census_incomplete_v1`, `mapping_census_drift_v1`,
`native_parser_unproven_v1`, `explicit_bzero_unproven_v1`,
`munlock_failed_v1`, `madv_dontneed_failed_v1` and `unmap_failed_v1`.
This document stores no wire byte and cannot authorize replay.

`OllamaScenarioEvidenceV1` has exactly `format`, `evidence_generation`,
`attempt_id`, `authorization_hash`, `facet_id`, `scenario_id`,
`scenario_plan_hash`, `controller_plan_hash`, `installation_observation_hash`,
`model_lock_hash`, `candidate_profile_hash`, `candidate_recipe_hash`,
`access_policy_hash`, `custody_policy_hash`, `operation_lease_hash`,
`limits_hash`, `facet_artifact_format`, `facet_artifact_hash`,
`broker_identity_hash`, `candidate_subgroup_hash`, `handoff_chain_hash`,
`process_transition_set_hash`, `peer_transition_set_hash`,
`runner_transition_set_hash`, `fork_window_observation_hash`,
`operation_effect_timing_set_hash`, `native_wire_parser_policy_hash`, nullable
`native_wire_parser_observation_hash`, `http_wire_buffer_observation_hash`,
`transcript_metadata_hash`,
`resource_observation_set_hash`, `ambient_sink_catalog_hash`,
`ambient_sink_observation_set_hash`, `egress_capture_hash`,
`log_capture_hash`, `capture_loss_count`, `exercised_branch`, `failures`,
`cleanup_proof_hash`, `availability`, `production_eligible`,
`pricing_status`, `egress_enforcement`, `telemetry_status`, `replay_support`,
`event_id`, `event_payload_hash`, and `observed_at`. Format is
`worldforge_ollama_scenario_evidence_v1`,
generation one; facet/scenario/artifact match one catalog row. `attempt_id` is
an independent domain ID, `event_id` is derived by the global domain-separated
Studio event-ID formula, and `event_payload_hash` is derived by the global
domain-separated Studio event-payload formula; every other named `*_hash` is an
ordinary already-complete document reference.
`exercised_branch` is respectively `nonstream_terminal_success_v1`,
`pre_send_cleanup_v1` or `post_send_disconnect_v1`; `failures` is exactly the
empty array; loss is zero; and the final six status values are exactly
`observed_nonproduction`, false, `unavailable`, `not_enforced`,
`observed_not_enforced`, and `not_claimed`. A `scenario_unusable_v1` facet or
nonempty fatal failure cannot create this document. `protocol_text` requires a
non-null native parser observation with
`result_class=bounded_zero_copy_observed_v1`; `control_pre_send` requires the
field null; and `control_post_send` requires it null unless bounded bytes were
actually inspected, in which case only that same successful result is valid.
The parser policy hash must byte-equal the ControllerPlan and AccessPolicy.
Whenever the parser observation is non-null it must byte-equal the wire-buffer
observation's `structured_parse_observation_hash`, and its request/response
mapping-observation hashes must byte-equal those in that buffer observation.
It is created only as the
target of `scenario_evidence_sealed_v1`; its event-free target body omits the
two event fields and has no sibling edge. The table qualifiers `preterminal`
and `terminal_bound_v1` are Store predicates, not document fields and never new
ScenarioEvidence hashes. `preterminal` means the exact committed document has
not yet been consumed by a terminal-attempt event. `terminal_bound_v1` means
that byte-identical immutable hash is already the `scenario_evidence_hash` of
the sourced `final_clean`; the transaction re-reads both documents and rejects
any other hash, terminal state or mutation.

`OllamaEvidenceEnvelopeV1` has exactly `format`, `envelope_generation`,
`attempt_id`, `authorization_hash`, `facet_id`, `scenario_id`,
`scenario_evidence_hash`, `terminal_attempt_hash`, `proven_recovery_hash`,
`terminal_execution_owner_hash`, `cleanup_proof_hash`, `limits_hash`,
`envelope_scope`, `internally_complete`, `availability`,
`production_eligible`, `catalog_admission_allowed`, `provider_content_present`,
`event_id`, `event_payload_hash`, and `sealed_at`. Format is
`worldforge_ollama_evidence_envelope_v1`, generation
one, scope is `one_declared_scenario_only_v1`, the two completeness/status
values are true/`observed_nonproduction`, and the last three booleans are false.
`attempt_id` is an independent domain ID, `event_id` is derived by the global
domain-separated Studio event-ID formula, and `event_payload_hash` is derived
by the global domain-separated Studio event-payload formula; every other named
`*_hash` is a backward already-complete document reference. It cannot reference the later private-artifact projection, any
runtime/catalog binding or another envelope. It exists only as the target of
`evidence_envelope_sealed_v1` after all three terminal source projections and
the exact `terminal_bound_v1` ScenarioEvidence are committed; its target body omits the two
event fields and has no sibling edge. The same transaction requires the unique
eligibility Store key absent and changes it to this finalized envelope hash.
An eligibility-abandonment hash rejects the seal permanently. A reboot after
the envelope hash already occupies that key does not create an abandonment or
rewrite any envelope field.

The canonical serializer emits UTF-8 JSON with the listed key order, no
insignificant whitespace, lowercase literals and shortest decimal integers.
Two mandatory serializer/hash vectors are:

```text
OllamaEvidenceLimitsV1 canonical length = 694
OllamaEvidenceLimitsV1 SHA-256 = a5bac04a7e5b515bccc27f99045de4a008ea40e509fa04b53150931ba2323569
OllamaCandidateRecipePolicyV1 vector: candidate/profile through required-binding
hashes are respectively 00*32,11*32,22*32,33*32,44*32,55*32,66*32,77*32;
policy_generation=1; canonical length = 892
OllamaCandidateRecipePolicyV1 SHA-256 = c5a74e73a4c53e77a1c7618104c7d7e009efef2844e3816f266104e97ca5ac12
```

The Limits vector uses exactly the field values and order frozen above. In the
recipe-policy vector each `NN*32` means the 64-character lowercase hex string,
not raw bytes. An implementation must publish byte fixtures for every schema
in this section and make both vectors fail before any construction authority is
enabled; these vectors validate serialization only and grant no authority.

### Authenticated one-use evidence authority

Only a construction-owned `StudioHumanDecisionAuthority` root may issue
`worldforge_ollama_evidence_authorization_v1`. It first verifies one
authenticated durable Director decision that binds the exact controller-plan,
candidate-profile, candidate-recipe-policy, binary-closure, model-lock,
access-policy, facet, scenario,
scenario-plan, custody-policy, operation-lease-policy, systemd-policy,
custody-proof, exact limits and exact deadline-action static-install hashes, an
exclusive expiry and decision generation. Chat text, asserted
reviewer/director labels, modal clicks and in-memory approval cannot substitute.

The exact final frozen `OllamaEvidenceAuthorizationV1` type has only these keys:
`format`, `authorization_id`, `director_principal_id`,
`director_authentication_hash`, `decision_id`, `decision_hash`,
`decision_generation`, `controller_plan_hash`, `candidate_profile_hash`,
`candidate_recipe_policy_hash`, `binary_closure_hash`, `model_lock_hash`,
`access_policy_hash`, `facet_id`,
`scenario_id`, `scenario_plan_hash`, `custody_policy_hash`,
`operation_lease_policy_hash`, `systemd_policy_hash`, `custody_proof_hash`,
`deadline_action_static_install_hash`, `limits_hash`,
`issued_at`, `expires_at` and `nonce`. `format` is exactly
`worldforge_ollama_evidence_authorization_v1`; its content/document hashes follow
the canonical SHA-256 rule above, while `director_authentication_hash` follows
that same rule over the separately frozen durable Director authentication
evidence document,
generation is a positive JavaScript-safe integer, times are canonical UTC
strings with exclusive expiry, and nonce is 32 random bytes encoded lowercase
hex. Before constructing this authorization document, the issuing root derives
`authorization_id` exactly with the domain formula above from the already
authenticated `decision_id`, positive `decision_generation` and that raw nonce.
The result is exactly 64 lowercase hexadecimal characters; it contains no
authorization-content hash, target-body hash, event hash or consumer hash and
can therefore be used as an independent scalar identity. Its frozen v1
serializer emits exactly those built-in scalars as bounded
canonical JSON; its content hash is lowercase SHA-256 of those bytes. The root
registers the issued capability and full-field snapshot by exact object identity.
Copies, subclasses, `object.__new__` instances, owner swaps,
field/serializer/hash drift and a capability issued by any other root are
rejected.

Before any evidence scratch, operation lease, broker/candidate process or
evidence socket, `StudioStore` atomically checks the exact authorization-content
hash as the evidence request fingerprint. An exact terminal duplicate returns
only its private evidence/failure and recovery state; it grants no capability or
effect. An exact nonterminal duplicate first checks the durable execution owner.
When its exact owner identity/start/pidfd is kernel-proven live, the duplicate
returns only the existing private state and **must not** acquire recovery, create
a manager transaction or perform any effect. Recovery is eligible only after an
exact kernel owner-death proof or a completed authenticated owner revocation as
defined below. Otherwise one transaction requires the Studio-wide
evidence-launch lock to be free, revalidates expiry/revocation, consumes the
exact `(decision_id, decision_generation, nonce)` tuple, acquires the lock,
creates execution-owner epoch 1 and commits `consumed_no_resources`; CAS failure
consumes nothing. A consumed attempt can never rerun.

The durable attempt state machine is closed and ordered:

```text
fresh --atomic consume--> consumed_no_resources
consumed_no_resources --CAS lease identity--> opening
opening --authenticated custody handoff CAS--> open
open --> final_clean | failed_clean | failed_cleanup_pending
opening | consumed_no_resources --> failed_clean | failed_cleanup_pending
```

The separate content-free `OllamaEvidenceExecutionOwnerV1` has exactly
`format`, `attempt_id`, `authorization_hash`, `linux_boot_id`,
`execution_owner_epoch`, `state`,
`owner_instance_id`, `owner_principal_hash`, nullable `owner_pid`, nullable
`owner_start_time`, nullable `owner_pidfd_identity_hash`, nullable
`operation_lease_hash`, `release_gate_id`, positive `generation`,
nullable `prior_owner_hash`, nullable `owner_death_proof_hash`, nullable
`authenticated_revocation_hash`, nullable
`boot_transition_owner_death_proof_hash`, nullable `owner_cutoff_hash`, nullable
`owner_cutoff_lower_boottime_ns`, nullable `owner_cutoff_upper_boottime_ns`,
nullable `recovery_fence_hash`, nullable `recovery_fence_boottime_ns`, nullable
`prior_recovery_owner_hash`, nullable `recovery_takeover_fence_hash`, nullable
`cleanup_proof_hash`, nullable `recovery_projection_hash`, `event_id`,
`event_payload_hash` and `committed_at`. `format` is exactly
`worldforge_ollama_evidence_execution_owner_v1`; state is only `owned`,
`recovering` or `terminal`, and the epoch is a positive JavaScript-safe integer.
The initial consume transaction creates `owned` at epoch 1 with the exact
construction-owned main identity, authenticated current Linux boot ID and newly
retained self-pidfd proof.
`owned` requires every death/revocation/boot-transition, cutoff,
recovery-fence, prior-recovery-owner,
recovery-takeover, cleanup and recovery hash to be null. Same-boot `recovering`
requires the exact non-null cutoff and recovery-fence fields, exactly one of
owner-death/revocation, and null boot-transition proof; reboot-abort
`recovering` instead requires canonical-null cutoff fields, an exact
`reboot_abort_v1` recovery fence whose boot IDs differ, and the bound
non-null boot-transition owner-death proof with both same-boot proof fields
null. Both require null cleanup/recovery hashes.
`terminal` requires both exact cleanup/recovery hashes; a normal
terminal may have null cutoff fields, while a recovery terminal must preserve
the applicable nullable cutoff, exact recovery fence and takeover chain
unchanged.

`owner_death_proof_hash` may name only a frozen content record containing exact
attempt/owner hash/epoch/generation, PID/start, pidfd fingerprint, retaining
kernel-observer authority hash, pidfd `poll`/`epoll` result, exact
`/proc/<pid>/stat` PID/start/state observation, a same-boot observation interval
and observation hash. The construction-owned `StudioOwnerLivenessObserver`
must retain the exact pidfd before the owner begins effects and must survive
that owner; this repeats before every recovery-takeover owner may act. For a
non-child it proves death only when the retained pidfd becomes
readable/HUP and `/proc` proves the PID/start tuple absent, reused or zombie;
a non-child never uses a child-reaping API. A raw PID
lookup, process name or inode scan is never signal authority.
`authenticated_revocation_hash` may name only a durable revocation issued
either by that exact registered owner as
`owner_self_failure_v1` after it closes new-effect admission, or by the same
Studio human-decision root as `director_forced_v1`. Both bind the exact attempt,
owner hash/epoch/generation, Director decision generation, reason,
issued/expiry times, issuer identity and one-use nonce. Revocation is complete
only after its expected-owner CAS is acknowledged; a request, heartbeat gap or
modal state is not completion.

The frozen `OllamaEvidenceOwnerCutoffV1` has exactly `format`, `attempt_id`,
`authorization_hash`, `source_execution_owner_epoch`,
`source_execution_owner_hash`, `source_owner_generation`, `cause`,
`linux_boot_id`, `last_proven_owner_valid_boottime_ns`,
`cutoff_observation_before_boottime_ns`,
`cutoff_observation_after_boottime_ns`, `cutoff_lower_boottime_ns`,
`cutoff_upper_boottime_ns`, nullable `owner_death_proof_hash`, nullable
`authenticated_revocation_hash`, `liveness_observer_identity_hash` and
`committed_at`. `format` is exactly `worldforge_ollama_owner_cutoff_v1`; cause
is only `kernel_owner_loss_v1` or `authenticated_revocation_v1`. A death proof
requires one last exact live observation followed by the retained-pidfd and
`/proc` proof bracketed by the before/after samples; its conservative interval
is `[last_proven_owner_valid_boottime_ns,
cutoff_observation_after_boottime_ns]`. A revocation brackets the
expected-owner Store CAS with the same-clock before/after samples and uses
`[cutoff_observation_before_boottime_ns,
cutoff_observation_after_boottime_ns]`; its last-valid sample is that exact
before sample. The lower bound must equal the applicable first value above and
the exact inequalities are
`last_proven_owner_valid_boottime_ns <=
cutoff_observation_before_boottime_ns <=
cutoff_observation_after_boottime_ns`,
`cutoff_lower_boottime_ns <= cutoff_upper_boottime_ns`. Neither cause may
invent a point timestamp inside its uncertainty interval.

The frozen, acyclic `RecoveryFenceDocumentV1` has exactly `format`,
`attempt_id`, `authorization_hash`, `fence_kind`,
`prior_execution_owner_epoch`, `prior_execution_owner_hash`,
`prior_owner_instance_id`, `prior_owner_principal_hash`, nullable
`prior_owner_pid`, nullable `prior_owner_start_time`, nullable
`prior_owner_pidfd_identity_hash`, `new_execution_owner_epoch`,
`new_owner_instance_id`, `new_owner_principal_hash`, nullable `new_owner_pid`,
nullable `new_owner_start_time`, nullable `new_owner_pidfd_identity_hash`,
`prior_linux_boot_id`, `new_linux_boot_id`, `store_revision`, nullable
`owner_cutoff_hash`, nullable `owner_death_proof_hash`, nullable
`authenticated_revocation_hash`, nullable
`boot_transition_owner_death_proof_hash`, `prior_recovery_fence_hash`,
`committed_boottime_ns` and `committed_at`. `format` is exactly
`worldforge_ollama_recovery_fence_document_v1`; `fence_kind` is only
`execution_owner_recovery_v1`, `recovery_owner_takeover_v1` or
`reboot_abort_v1`; `new_execution_owner_epoch` is exactly the checked prior
epoch plus one; and `store_revision` is the positive revision CASed by the same
StudioStore transaction. The first fence for an attempt names 64 zeroes as its
prior fence; every later fence, including a reboot-abort fence created after an
earlier recovery fence, names the exact preceding fence hash. Normal and
takeover fences
keep both boot IDs equal, require a non-null cutoff, and require exactly one of
the death/revocation proof hashes while the boot-transition field is null. A
reboot fence requires unequal authenticated boot IDs, a null cutoff, a non-null
boot-transition owner-death proof and null same-boot death and revocation
fields. No document may populate both proof families. Its hash is the exact
domain-separated formula above.

The fence document contains no new-owner projection, release, tombstone,
capability, recovery-projection or cleanup hash. The new owner projection binds
`recovery_fence_hash` to this document. Initial recovery keeps
`recovery_takeover_fence_hash` null; a recovery-owner takeover sets it equal to
the same current fence hash. Prior documents are reachable only through the
one-way `prior_recovery_fence_hash` chain, so no consumer can enter the fence
hash preimage.

An `owned` record may enter same-boot `recovering` only when StudioStore
atomically validates either that exact owner-death proof or a completed
authenticated revocation bound to the expected owner hash/generation. The
separate reboot transition below uses only its exact authenticated unequal-boot
proof and never this same-boot path. One same-boot CAS over the
expected owner hash/epoch/generation commits the cutoff document, increments
the epoch, constructs and hashes the exact `execution_owner_recovery_v1`
RecoveryFenceDocument, changes state to `recovering`, writes that immutable
recovery-fence hash and same-boot `CLOCK_BOOTTIME` fence, and applies exactly
one R0--R9 row from the closed recovery table below in the same joint event.
Only R1--R5 terminalize the mutable release as `recovery_fenced` and rebind the
lifecycle; R0 has no pair, and R6--R9 preserve both immutable projections as
sources. The transaction invalidates every outstanding old-epoch release
snapshot and unused deadline-action capability before any recovery observation
or kill. A
fire-committed deadline-action finalization has the sole, separately bounded
exception defined below. ACK loss returns the exact committed cutoff/fence.
Changed proof or a stale epoch is rejected.

A recovery owner can itself be lost. `recovering(old owner/epoch) ->
recovering(new owner/epoch+1)` is permitted only after the same retained-pidfd
plus `/proc` death proof for the exact prior recovery owner, or a completed
authenticated revocation of it. The single expected-owner CAS stores a new
cutoff and exact `recovery_owner_takeover_v1` RecoveryFenceDocument, sets
`prior_recovery_owner_hash` to the old recovering projection, writes the new
hash to both current/takeover fence fields, increments the epoch/generation and
applies exactly one eligible R0/R6--R12 takeover row: only R10--R12 rebind a
mutable lifecycle, while R0/R6--R9 have no pair target. It fences every old
recovery action before the new owner may observe or kill.
Every manager, cleanup and projection write binds the current recovery epoch;
the only old-epoch write exception is the exact already-fire-committed,
finalization-only deadline-action append defined below. Otherwise a stale owner
cannot act. The new owner may continue
only idempotent cleanup and publication, never candidate execution. Failure to
prove the previous recovery owner's death/revocation or effect order leaves the
Studio launch lock closed.

Every snapshot issuance/acceptance and candidate effect is finally usable only
when the snapshot's `expires_boottime_ns`, its Acceptance time and the complete
effect/observation interval are all strictly less than
`cutoff_lower_boottime_ns` for every later owner-loss/revocation cutoff in its
attempt. An instant at either bound, an overlap, a missing cutoff observation
or unprovable order is non-evidence. A normally completed owner has no cutoff;
a same-boot recovery acquisition always commits one and invalidates all
outstanding snapshots. A reboot acquisition commits no `OwnerCutoff`, keeps
that reference canonical null and is fenced only by its exact unequal-boot
`BootTransition` proof. Recovery kills only the old epoch's retained/recoverable lease
domain, reaches the cleanup fixed point and never starts a replacement evidence
execution.

Normal or recovery completion publishes the exact `proven` recovery and
`terminal` execution owner in the single atomic acyclic transaction defined
below. No terminal owner can return to another state.

`consumed_no_resources` is an invariant: no lease identity has been persisted
and no manager effect, scratch, unit, cgroup, process, socket or device context
may exist. Main reads only the Linux boot ID and `CLOCK_BOOTTIME`, derives the
resource-free deterministic lease document, and CAS-commits its exact identity
and system-PID1 unit handle in `opening` **before** any manager create call,
broker, candidate subgroup or scratch root. `open` follows only after the live
outer unit,
mandatory broker main-loss lease, empty candidate subgroup, scratch root
and authenticated pidfd handoff are proven, and the exact timer/action,
tombstone key and `inert_armed` release gate are attested. A committed `open`
may request the atomic release transition. Candidate configuration disclosure,
fork/exec, listener acquisition and request send are usable as evidence only
when each binds a fresh current-epoch release snapshot and its separately
observed effect timing is strictly ordered before every cutoff/fence. This is an
evidence-classification rule, not a claim that a Store CAS atomically prevents a
later cross-process effect.

The content-free attempt projections are:

| State | Exact format | Exact additional keys |
|---|---|---|
| `consumed_no_resources` | `worldforge_ollama_evidence_consumed_no_resources_v1` | `decision_id`, `decision_generation`, `nonce_hash`, `recovery_id`, `recovery_nonce_hash`, `scenario_plan_hash`, `custody_policy_hash`, `operation_lease_policy_hash`, `limits_hash`, `launch_lock_generation`, `committed_at` |
| `opening` | `worldforge_ollama_evidence_opening_v1` | `consumed_hash`, `operation_lease_hash`, `lease_id`, `linux_boot_id`, `opened_boottime_ns`, `deadline_boottime_ns`, `timer_on_boot_usec`, `systemd_manager_identity_hash`, `systemd_unit_name`, `systemd_unit_object_path`, `systemd_deadline_timer_name`, `systemd_deadline_timer_object_path`, `systemd_deadline_action_name`, `systemd_deadline_action_object_path`, `main_loss_lease_contract_hash`, `custody_proof_hash`, `opening_at` |
| `open` | `worldforge_ollama_evidence_open_v1` | `opening_hash`, `operation_lease_live_hash`, `systemd_invocation_id`, `systemd_properties_hash`, `broker_ready_hash`, `deadline_action_static_install_hash`, `deadline_action_load_observation_hash`, `timer_start_transaction_hash`, `deadline_timer_invocation_id`, `deadline_timer_properties_hash`, `pre_release_timer_clock_observation_hash`, `deadline_action_lifecycle_hash`, `candidate_release_projection_hash`, `deadline_tombstone_key_hash`, `runtime_max_usec`, `custody_proof_hash`, `handoff_chain_hash`, `candidate_subgroup_hash`, `scratch_root_hash`, `opened_at` |
| `final_clean` | `worldforge_ollama_evidence_final_clean_v1` | `open_hash`, `scenario_evidence_hash`, closed `cleanup_proof_mode`, `cleanup_proof_hash`, `finalized_at` |
| `failed_clean` | `worldforge_ollama_evidence_failed_clean_v1` | `source_projection_hash`, closed `failure_code`, closed `effect_classification`, closed `cleanup_proof_mode`, `cleanup_proof_hash`, `failed_at` |
| `failed_cleanup_pending` | `worldforge_ollama_evidence_failed_cleanup_pending_v1` | `source_projection_hash`, closed `failure_code`, closed `effect_classification`, `cleanup_observation_hash`, `recovery_id`, `failed_at` |

The `open` handoff lineage is only the exact sequence of authenticated
HandoffOffer/HandoffAcceptance records summarized by `handoff_chain_hash`.
There is no second broker-handoff field, document or alias.

Every attempt projection also has exactly `format`, `state`, `attempt_id`,
`authorization_hash`, `execution_owner_epoch`, `execution_owner_hash`, positive
`generation`, `prior_attempt_hash`, `event_id` and `event_payload_hash`.
For every non-consume transition, `execution_owner_epoch` and hash name the
already committed current owner immediately before that attempt transition.
Initial consume acquires the lock and creates both owner/attempt records in one
transaction: the attempt body has
the table-declared sibling edge to owner body ordinal 1, and finalization fills
`execution_owner_hash` with that earlier finalized owner complete hash. A
terminal attempt deliberately names the pre-terminal owner.
The later terminal-owner projection points to the proven recovery without a
hash cycle. A stale or cross-attempt owner is invalid. `attempt_id` is lowercase SHA-256 of the ASCII domain
`worldforge-ollama-evidence-attempt-v1`, one NUL byte and the lowercase
authorization hash. The first `prior_attempt_hash` is 64 zeroes; later attempt projections name
the exact prior hash and increment generation by one. Each projection is bounded
canonical JSON, addressed by lowercase SHA-256 and CAS-committed over
`(attempt_id, generation, prior_attempt_hash)`. The three terminal attempt
states are immutable.

Before the consume transaction, main independently obtains another 32-byte
kernel-CSPRNG recovery nonce and derives `recovery_id` with the exact domain
formula above. The ID and `recovery_nonce_hash=SHA256(raw recovery nonce)` are
64 lowercase hexadecimal characters and are persisted in
`consumed_no_resources`; the raw nonce is zeroized after the acknowledged
consume. Neither scalar contains an attempt projection, recovery projection,
target-body, event or other consumer hash. Every later recovery projection and
`failed_cleanup_pending` attempt must repeat this exact prederived ID; no caller
may choose, regenerate or derive it from a terminal target.

The five projection-chain fields are exact and nullable. `prior_owner_hash`,
`prior_recovery_hash`, `prior_release_hash`, `prior_lifecycle_hash` and
`prior_terminal_hash` are JSON `null` on generation 1 of their respective
document type. At generation greater than 1 each is exactly the 64-lowercase-
hex complete content hash of generation minus one for the same attempt and
chain, and generation must increment by exactly one. A zero hash, domain ID,
target-body/event hash, non-immediate ancestor, cross-attempt hash, omitted
field or string `"null"` is invalid. The distinct nullable
`prior_recovery_owner_hash` in an execution-owner takeover, when present, is
likewise the complete prior recovering-owner projection hash and never the
recovery-projection ID or body hash.

Every Store transition or journalled external effect uses one frozen, acyclic
`StudioTransitionEventPayloadV1` with exactly `format`, `event_kind`,
`attempt_id`, `attempt_revision_before`, `attempt_revision_after`,
`transaction_id`, `transaction_revision`, `transaction_request_hash`,
`store_revision_before`,
`store_revision_after`, `source_refs`, `target_refs`, `cause_ref`,
`prior_event_hash` and `committed_at`. `format` is exactly
`worldforge_ollama_studio_transition_event_payload_v1`; all five revision fields are
nonnegative JavaScript-safe integers, transaction revision starts at one and
increments by one per attempt, and `store_revision_after` is exactly the CASed
successor of `store_revision_before`. The first event names 64 zeroes as
`prior_event_hash`; every later event names the exact prior event-payload hash.
`transaction_request_hash` is the ordinary canonical document hash of the
bounded pre-effect request containing the intended event kind, source refs,
ordered target formats and, for an external effect, its exact method/request
bytes hash. It contains no result or target-under-construction hash.

Each ordered `source_refs` element has exactly `tag`, `document_format`,
`document_hash` and `revision`. `tag` is only `none_v1`,
`attempt_projection_v1`, `execution_owner_projection_v1`,
`recovery_projection_v1`, `candidate_release_projection_v1`,
`deadline_action_lifecycle_projection_v1`, `launch_lock_projection_v1`,
`systemd_terminal_projection_v1`, `handoff_chain_v1`,
`release_snapshot_v1`, `release_snapshot_acceptance_v1`,
`operation_effect_timing_v1`, `cleanup_proof_v1`,
`manager_effect_result_v1`, `deadline_tombstone_v1`,
`deadline_action_capability_registration_v1`,
`deadline_credential_source_v1`, `deadline_credential_file_observation_v1`,
`deadline_credential_cleanup_proof_v1`,
`deadline_action_reboot_abandonment_v1`,
`evidence_eligibility_abandonment_v1`, `reboot_abort_observation_v1`,
`zero_allocation_journal_v1`, `scenario_evidence_v1` or
`evidence_envelope_v1`. `none_v1` is the sole explicit
no-source sentinel and requires the other three fields canonical null; every
other tag requires the complete hash, exact format and revision of an already
committed document that the same transaction re-reads. An empty array, a
caller-supplied hash, a target-under-construction or an inferred previous
projection is invalid.

Each ordered `target_refs` element has exactly `tag`, `document_format`,
`transition_target_body_hash` and `revision`. Its tag is only one of the
non-`none_v1` source tags above or `handoff_acceptance_v1`,
`owner_cutoff_v1`, `recovery_fence_v1` or
`private_evidence_artifact_v1`.

Every target ref hashes a separate, event-free
`StudioTransitionTargetBodyV1` with exactly `format`, `attempt_id`,
`transaction_id`, `event_kind`, zero-based `target_ordinal`, `target_tag`,
`document_format`, `store_revision`, `schema_body`, `independent_refs` and
`sibling_body_refs`. `format` is exactly
`worldforge_ollama_transition_target_body_v1`. `schema_body` is the target's
exact bounded canonical key/value object with its declared `event_id`,
`event_payload_hash`, `authentication_hash` and every same-event relation field
listed in the topological table below omitted. No undeclared field is
synthesized. Each ordered `independent_refs` entry has exactly `field_name`,
`ref_kind` and `ref_value`; `ref_kind` is only `domain_id_v1` or
`committed_source_hash_v1`, and its value must be, respectively, an independently
derived 64-lowercase-hex identifier or an already committed complete source
hash. It contains exactly every reference-valued `schema_body` field classified
by that target schema as one of those two kinds, ordered first by declared key
order and then by array ordinal; omission, duplication or a reference with no
matching schema value is invalid. Each ordered `sibling_body_refs` entry has exactly `field_name`,
`target_ordinal`, `document_format` and `transition_target_body_hash`; its
ordinal must be strictly lower than the containing body's ordinal. Both arrays
are capped at 512 entries, names/formats at 128 ASCII bytes, `schema_body` at
262,144 canonical UTF-8 bytes and the whole document at 270,336 bytes. Unknown
keys, duplicate field names, forward/self edges, a complete same-event sibling
hash, or a sibling not listed in the table are rejected.

Construction is mechanical. StudioStore first freezes bodies in ordinal order;
a later body may name only an independently derived ID, a complete already
committed source, or an earlier sibling body hash. It then hashes the event
payload and derives `event_id`. Targets are finalized again in ordinal order:
only schemas that declare `event_id` and/or `event_payload_hash` receive those
exact values, and each declared same-event relation field is filled with the
already finalized complete hash of the earlier sibling whose body hash was
committed in `sibling_body_refs`. An `authentication_hash` is never copied or
filled from the event: after event and relation fields resolve, it is computed
independently from that target's exact HMAC key/domain over its canonical
preimage with only its own authentication field omitted. The complete target
hash is computed last and is never fed into any body or event that precedes it.
The atomic transaction retains each exact TargetBody document, its hash, the
event and every finalized target; lookup/ACK reconciliation revalidates all
four layers and never reconstructs a body from mutable target bytes.
An inbound preauthenticated target that declares no event or sibling relation
is independently revalidated byte-for-byte and cannot be mutated by the event.

`revision` is always the trusted StudioStore commit revision, not a caller
counter or a document's internal sequence. Every non-sentinel source ref names
the exact revision at which that complete source row was committed. Every
target ref names this transaction's common `store_revision_after`; all targets
are committed by that one transaction or none are. `none_v1` alone has a null
revision. Store revision advances exactly once per successful event transaction,
so ordered multi-target writes do not manufacture intermediate source states.

`cause_ref` has exactly `tag`, `document_format`, `document_hash` and `revision`.
Its tag is only `none_v1`, `authorization_v1`, `director_decision_v1`,
`control_message_v1`, `manager_reply_v1`, `deadline_timer_v1`,
`owner_death_proof_v1`, `authenticated_revocation_v1`,
`boot_transition_owner_death_proof_v1`, `operation_effect_observation_v1`,
`credential_file_observation_v1`,
`owner_cutoff_v1`, `recovery_fence_v1`, `recovery_projection_v1` or
`cleanup_observation_v1`; the same
null/non-null rules apply. The event payload contains no `event_id`,
`event_payload_hash` or `authentication_hash`, and its serializer rejects those
keys. The event-payload, transaction and event IDs use only the exact formulas
above. Thus target bodies can bind the event without a hash cycle.

The transition-only schemas below are complete; no abstract projection tag is
permitted. Each serializer emits the listed keys in that order, accepts only
built-in JSON types, rejects bool-as-int, unknown/duplicate/missing keys and
noncanonical encodings, and is bounded to 32,768 canonical UTF-8 bytes unless a
smaller bound is stated. Every `*_id`/`*_hash` value is exactly 64 lowercase
hex, every epoch/generation/count/byte/timestamp integer is in
`0..9007199254740991` unless narrowed below, and every `committed_at` or
`published_at` is a canonical UTC string of at most 35 ASCII bytes. Each
complete document uses the ordinary canonical-document SHA-256 rule. None of
these transition-only schemas declares `authentication_hash`.

`OllamaEvidenceLaunchLockV1` has exactly `format`, `scope`, `state`, nullable
`lock_owner_attempt_id`, `launch_lock_generation`, nullable
`last_recovery_hash`, nullable `prior_lock_hash`, nullable `event_id`, nullable
`event_payload_hash` and `committed_at`. `format` is exactly
`worldforge_ollama_evidence_launch_lock_v1`; `scope` is exactly
`studio_wide_ollama_evidence_v1`; and state is only `unlocked` or `locked`.
The unique Store bootstrap row is generation zero, unlocked, with all five
nullable identity/hash/event fields null. Every acquisition/release increments
generation exactly once, names the previous complete lock hash in
`prior_lock_hash`, and has non-null event fields. Acquisition requires `locked`
and the independently prederived current `attempt_id` while preserving the
source's `last_recovery_hash`; release requires
`unlocked`, null owner and the exact non-null proven recovery hash. No other
transition exists. Its event-free target body omits only the two event fields;
`lock_owner_attempt_id`, when present, is a `domain_id_v1`, and
`last_recovery_hash`/`prior_lock_hash`, when present, are
`committed_source_hash_v1`; it has no sibling body ref.

`OllamaDeadlineActionCapabilityRegistrationV1` has exactly `format`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`,
`execution_owner_epoch`, `execution_owner_hash`, `capability_id`,
`capability_hash`, `action_invocation_id`, `capability_nonce_hash`, `key_id`,
`store_method_set_hash`, `deadline_action_static_install_hash`, `limits_hash`,
`state`, `registration_generation`, `event_id`, `event_payload_hash` and
`committed_at`. `format` is exactly
`worldforge_ollama_deadline_action_capability_registration_v1`; state is only
`registered_unconsumed_v1`; and generation is exactly one. The capability hash
is the complete authenticated capability document, its nonce/key hashes name
the exact distinct raw 32-byte values, and the method-set/static-install/limits
hashes must equal the authorization and lease. The two event fields are
non-null. Its target body omits those event fields; its independent refs are
the domain IDs `attempt_id`, `capability_id`, `action_invocation_id` followed by
the committed authorization, lease, owner, static-install and limits hashes in
declared-key order. `capability_hash`, nonce/key and method-set hashes remain
opaque integrity-digest scalars in `schema_body`, not graph edges. It has no
sibling ref. Consumption or recovery never mutates this registration: the
one-use nonce, tombstone and owner/recovery fence carry later state.

`OllamaDeadlineCredentialSourceV1` has exactly `format`, `attempt_id`,
`authorization_hash`, `operation_lease_hash`, `execution_owner_epoch`,
`execution_owner_hash`, `linux_boot_id`, `capability_id`, `capability_hash`,
`capability_registration_hash`, `action_invocation_id`,
`deadline_action_static_install_hash`, `credential_name`,
`parent_realpath`, `parent_device`, `parent_inode`, `parent_mount_id`,
`parent_mode`, `parent_uid`, `parent_gid`, `source_basename`, `source_realpath`,
`expected_source_mode`, `expected_source_uid`, `expected_source_gid`,
`decryption_policy_hash`, `maximum_ciphertext_bytes`, `state`,
`source_generation`, nullable `prior_credential_source_hash`, nullable
`source_device`, nullable `source_inode`, nullable `source_mount_id`, nullable
`source_mode`, nullable `source_uid`, nullable `source_gid`, nullable
`ciphertext_size`, nullable `ciphertext_sha256`, nullable
`created_boottime_ns`, nullable `file_fsync_observation_hash`, nullable
`parent_fsync_observation_hash`, nullable `writer_fd_close_observation_hash`,
nullable `creation_store_revision`, `event_id`, `event_payload_hash` and
`committed_at`. `format` is exactly
`worldforge_ollama_deadline_credential_source_v1`; state is only `pending_v1`
or `ready_v1`; source generation is one or two. Parent and source paths are
absolute normalized paths of at most 4,096 UTF-8 bytes; parent is exactly
`/run/worldforge-ollama-evidence-credentials`; the basename is the
single exact `<lease_id>.cred` component with no slash, dot component or
alternate escape; source realpath is exactly parent plus `/` plus that
basename; `expected_source_mode` is decimal `256` (permission bits octal
`0400`); a ready `source_mode` has `S_IFMT=S_IFREG` and permissions exactly
`0400`; all identity
integers are nonnegative `u53`; and the positive maximum is at most 65,536.
The name is exactly
`worldforge.deadline-action-store-capability-v1`. Parent identity, expected
owner and decryption policy are resolved from the already completed static
install/policy and are never ambient defaults.

`pending_v1` is the durable Store registration that MUST commit before any
file-creation syscall. It has generation one, null prior and every nullable
actual-file/creation field null. `ready_v1` has generation two, names the
complete pending source as prior, preserves every immutable policy/path field,
and requires every actual-file, timestamp, fsync/close and positive creation-
revision field non-null. Its actual mode/owner equal the expected values;
ciphertext size is in `1..maximum_ciphertext_bytes`; and SHA-256 covers the
exact bytes durably written to that exact dev/inode/mount identity. Ready is a
CAS from the exact pending Store revision only after file and parent fsync plus
writer-FD close. No file bytes, plaintext or key enter either document.

Only after pending is durably acknowledged may the fixed native credential
writer use the policy-bound retained `/run` dirfd and open the single
`worldforge-ollama-evidence-credentials` child component with
`openat2(O_PATH|O_DIRECTORY|O_CLOEXEC,
RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)` and revalidate its
dev/inode/mount/mode/owner. It creates exactly the registered basename relative
to that retained dirfd with
`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode `0400`; no truncation,
rename, temporary alternate or absolute-path reopen is allowed. It `fchown`s
the registered owner, `fchmod`s `0400`, writes the bounded ciphertext with
checked full-write semantics, fsyncs the file, re-fstats the exact FD, fsyncs
the parent dirfd, zeroizes its ciphertext working buffer, closes the writer FD,
and only then CASes ready with the observed identity/hash/revision. Failure or
crash before pending proves no create authority; after pending but before
create it follows the absent pending cleanup branch; after create but before
ready it follows authenticated pending-file cleanup; and after ready it follows
exact-ready-inode cleanup. No retry creates or overwrites a second path.

The Store key is `(attempt_id,action_invocation_id,deadline_credential_source_v1)`.
The pending and ready target bodies omit their event fields; domain refs are
attempt, capability and action-invocation IDs; committed sources are
authorization, lease, owner, capability registration and, for ready only, the
prior pending source in declared-key order. `capability_hash` and
`deadline_action_static_install_hash` are opaque authenticated hashes already
byte-matched by the registration.
There is no sibling edge. An ACK-loss lookup returns the one exact generation;
copy, alternate path, changed parent, skipped pending, second ready generation
or ready bytes not produced by the registered creation is rejected.

`OllamaDeadlineCredentialFileObservationV1` has exactly `format`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`,
`execution_owner_epoch`, `execution_owner_hash`, `linux_boot_id`,
`capability_registration_hash`, `pending_credential_source_hash`,
`action_invocation_id`, `parent_realpath`, `parent_device`, `parent_inode`,
`parent_mount_id`, `parent_mode`, `parent_uid`, `parent_gid`,
`source_basename`, `source_realpath`, `source_device`, `source_inode`,
`source_mount_id`, `source_mode`, `source_uid`, `source_gid`,
`ciphertext_size`, `ciphertext_sha256`, `created_boottime_ns`,
`file_fsync_observation_hash`, `parent_fsync_observation_hash`,
`writer_fd_close_observation_hash`, `ciphertext_buffer_zeroization_hash`,
`source_create_journal_hash`, `observation_loss_count`, `result_class`,
`observation_generation`, `event_id`, `event_payload_hash` and `observed_at`.
Its format is exactly
`worldforge_ollama_deadline_credential_file_observation_v1`; result class is
exactly `created_fsynced_closed_v1`; generation is one; and loss is zero. Every
path, identity, mode, owner and bound obeys the corresponding pending-source
rule. The source is a regular file with permissions exactly `0400`, ciphertext
size is in `1..pending.maximum_ciphertext_bytes`, and every observation hash is
the SHA-256 of its exact bounded content-free native observation rather than a
caller assertion.

This observation can be committed only by
`deadline_credential_file_observation_sealed_v1` after the pending registration
is durable and after the exact file write, file fsync, re-fstat, parent fsync,
ciphertext-buffer zeroization and writer-FD close have all completed. Its event
re-reads the current `opening` attempt, exact `owned` execution owner,
capability registration and pending source. The target body omits the two event
fields; its independent refs are attempt and action-invocation IDs; its
committed sources, in declared-key order, are authorization, lease, owner,
capability registration and pending source. All other named observation hashes
remain opaque content digests in `schema_body`; there is no sibling edge.

The subsequent `deadline_credential_source_ready_v1` event accepts only
`cause_ref.tag=credential_file_observation_v1` with this exact format, complete
hash and Store revision. It byte-matches every immutable pending field and every
actual-file/fsync/close field, sets `creation_store_revision` to that cause
revision, and then CASes pending to ready. An unknown cause, a generic control
message, another observation format, stale revision, substituted hash/identity,
nonzero loss or second observation/ready generation is rejected. The
observation is content-free and grants no file, manager, Store or execution
authority.

The post-capability `OllamaDeadlineActionLoadRecipeV1` has exactly `format`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`,
`execution_owner_epoch`, `execution_owner_hash`, `systemd_manager_identity_hash`,
`deadline_action_recipe_hash`, `deadline_action_static_install_hash`,
`capability_registration_hash`, `credential_source_hash`, `unit_name`,
`unit_object_path`, `dbus_method`, `dbus_signature`, `request_bytes_hash`,
`limits_hash` and `derived_at`. Its format is exactly
`worldforge_ollama_deadline_action_load_recipe_v1`; credential source must be
the completed `ready_v1` generation; method/signature are exactly
`LoadUnit`/`s->o`; and request bytes are the exact canonical D-Bus request for
that one unit. It is derived only after ready commits and points one-way to the
prelease static-action recipe. It is not part of, and is never hashed by, the
authorization, capability, lease ID, OperationLease or prelease recipe. The
`static_action_load_v1` manager result's `request_hash` is exactly this complete
load-recipe hash; no manager/unit request may infer or substitute the source.

`OllamaDeadlineCredentialCleanupProofV1` has exactly `format`, `attempt_id`,
`authorization_hash`, `operation_lease_hash`, `execution_owner_epoch`,
`execution_owner_hash`, `source_linux_boot_id`, `observed_linux_boot_id`,
`capability_registration_hash`, `capability_hash`, `action_invocation_id`,
`source_state`, nullable `credential_source_hash`, `cleanup_branch`,
`cleanup_generation`, nullable `prior_cleanup_proof_hash`,
`parent_identity_before_hash`, `source_path_derivation_hash`,
`source_create_journal_hash`, nullable
`observed_source_file_identity_hash`, nullable
`ciphertext_capability_authentication_hash`, `source_fd_closure_hash`,
`plaintext_key_zeroization_hash`, `ciphertext_buffer_zeroization_hash`,
`pre_unlink_lookup_result`, `unlink_result`, `parent_fsync_observation_hash`,
`post_unlink_lookup_result`, `parent_identity_after_hash`,
`observation_loss_count`, `result_class`, `event_id`, `event_payload_hash` and
`cleaned_at`. Format is exactly
`worldforge_ollama_deadline_credential_cleanup_proof_v1`; source state is only
`not_registered_v1`, `pending_v1` or `ready_v1`; cleanup branch is only
`normal_v1`, `failure_v1`, `recovery_v1` or `reboot_v1`; pre-lookup is only
`enoent_v1|exact_regular_file_v1`, post-lookup is exactly `enoent_v1`, unlink
result is only `not_needed_absent_v1` or
`authenticated_exact_inode_unlinked_v1`, loss is zero and result is
`credential_source_clean_v1`. Cleanup generation is a positive `u53`; it is
one with null prior for the first proof and otherwise exactly prior generation
plus one with the immediately preceding complete cleanup-proof hash. The two parent hashes prove the same pinned
parent dev/inode/mount/mode/owner; both zeroization hashes are non-null exact
observations, using `not_materialized_v1` when no plaintext or ciphertext
working copy ever existed.

`source_create_journal_hash` is the complete content-free ordered census of
every allowed credential-parent/source syscall and result for this attempt.
`not_registered_v1` requires a null source hash and that journal proving no
source-create syscall, pre-lookup ENOENT and no unlink. `pending_v1` names the
pending source; if the path is absent it uses the same absence result, while a
crash after creation but before ready may adopt the opened regular file only
after the pinned decryption policy authenticates its ciphertext to the exact
capability hash. `ready_v1` requires the opened file identity and ciphertext
digest to byte-match ready. Every present-file branch keeps the no-follow file
FD and pinned parent dirfd open, proves `fstatat(AT_SYMLINK_NOFOLLOW)` still
names that exact dev/inode immediately before `unlinkat`, unlinks only that
entry, proves the still-open authenticated file FD now has `st_nlink=0`, fsyncs
the parent, then proves ENOENT and unchanged parent identity.
Substitution, inability to authenticate pending bytes, inode race, inaccessible
parent, fsync/zeroization/close failure or loss produces no cleanup proof.
Reboot never reconstructs an old inode: it either proves current-boot ENOENT or
uses the same exact ready/pending authentication and unlink path when the exact
entry survives. `reboot_v1` additionally requires unequal source/observed boot
IDs and byte-equality with the reboot-abort observation's
`persistent_secret_sink_absence_hash`; that earlier observation contains no
future cleanup-proof hash. This proof contains no ciphertext, plaintext or key.

Its target body omits event fields; domain refs are attempt and action-
invocation IDs; committed sources are authorization, lease, current owner,
capability registration, any non-null credential source and any non-null prior
cleanup proof in key order;
`capability_hash` is the matching opaque authenticated hash from that
registration. It has no sibling edge. Once capability registration exists,
every normal, failure, recovery and reboot cleanup must commit exactly one such
proof for the active owner epoch before the outer cleanup proof; before source
registration, the `not_registered_v1` branch is mandatory. ACK loss returns the
same proof; a second proof in the same owner epoch is rejected, while a later
fenced recovery-owner epoch must append one new absence proof naming the prior
complete proof. Its transition source uses `none_v1` if and
only if source state is `not_registered_v1`; otherwise it is exactly the
complete pending or ready source named by `credential_source_hash`. A separate
trailing source is `none_v1` at cleanup generation one and the exact immediate
prior cleanup proof at every later generation.

`OllamaEvidenceManagerEffectResultV1` has exactly `format`, `attempt_id`,
`authorization_hash`, `operation_lease_hash`, `execution_owner_epoch`,
`execution_owner_hash`, `manager_effect_sequence`, `manager_operation`,
`method`, `request_hash`, `call_enter_boottime_ns`, `reply_state`, nullable
`reply_received_boottime_ns`, nullable `reply_bytes_hash`, nullable
`dbus_serial`, nullable `job_path`, `primary_unit_name`, `related_unit_names`,
`effect_class`, `allocation_state`, `systemd_manager_identity_hash`,
`observation_hash`, `limits_hash`, `event_id`, `event_payload_hash` and
`committed_at`. `format` is exactly
`worldforge_ollama_manager_effect_result_v1`; sequence is in `0..1048575` and
increments for each attempted PID1 call. `manager_operation` is only
`operation_start_v1`, `static_action_load_v1`, `static_action_ref_v1`,
`deadline_timer_start_v1`, `unit_stop_v1`, `unit_kill_v1`,
`terminal_read_v1`, `reset_failed_v1` or `unit_unref_v1`; `method` is only
`StartTransientUnit`, `LoadUnit`, `RefUnit`, `StopUnit`, `KillUnit`, `GetUnit`,
`GetAll`, `ResetFailedUnit` or `UnrefUnit`. Operation/timer start map to
`StartTransientUnit`; static load/ref map to `LoadUnit`/`RefUnit`; stop/kill map
to `StopUnit`/`KillUnit`; terminal read permits only `GetUnit|GetAll`; and
reset/unref map to `ResetFailedUnit`/`UnrefUnit`. `reply_state` is only
`received_v1` or `lost_or_ambiguous_v1`; `effect_class` is only `accepted_v1`,
`rejected_v1`, `unknown_v1` or `reconciled_existing_v1`; and
`allocation_state` is only `none_observed_v1`, `allocated_v1`,
`partial_or_unknown_v1` or `closed_v1`. A received reply requires non-null
reply time/hash and a D-Bus serial in `1..4294967295`; a lost/ambiguous reply
requires those three and `job_path` null, `effect_class=unknown_v1` and
`allocation_state=partial_or_unknown_v1`. `job_path` otherwise is null or one
canonical D-Bus object path at most 4,096 bytes. Unit names are 1..255 ASCII
bytes; `related_unit_names` is an ordered unique array of zero through eight
such names. A received reply has
`call_enter_boottime_ns <= reply_received_boottime_ns`; only a received reply
may be accepted, rejected or reconciled, and rejected requires
`none_observed_v1`. Both event fields are non-null. Its target body omits them, has
domain ref `attempt_id`, committed-source refs authorization/lease/owner/limits
in declared-key order, no sibling ref, and leaves request/reply/manager/
observation hashes as opaque digest scalars.

`OllamaEvidenceHandoffChainV1` has exactly `format`, `attempt_id`,
`authorization_hash`, `operation_lease_hash`, `execution_owner_epoch`,
`execution_owner_hash`, `chain_generation`, nullable `prior_chain_hash`,
`last_acceptance_hash`, `last_role`, `last_role_ordinal`,
`accepted_descriptor_count`, `event_id`, `event_payload_hash` and
`committed_at`. `format` is exactly
`worldforge_ollama_evidence_handoff_chain_v1`; generation starts at one and
increments once per accepted Offer. First generation has null prior; later
generations name the immediately preceding complete chain source. `last_role`
is only `deadline_timer_handle`, `deadline_action_handle`,
`operation_unit_handle`, `broker_pidfd`, `candidate_cgroup_kill_fd`,
`candidate_cgroup_events_fd`, `service_pidfd` or `runner_pidfd` in the frozen
handoff order. Non-runner role ordinal is exactly zero; runner ordinal is in
`0..28`. Descriptor count is zero for the three handle roles and one for every
pidfd/cgroup-FD role. Both event fields are non-null. Its target body omits the
event fields and `last_acceptance_hash`; domain ref is `attempt_id`, committed
source refs are authorization/lease/owner and any non-null prior chain, and its
sole sibling-body edge is `last_acceptance_hash` to ordinal zero. The finalized
field is the complete, independently HMAC-validated Acceptance hash.

`OllamaPrivateEvidenceArtifactPayloadV1` has exactly `format`,
`payload_generation`, `attempt_id`, `authorization_hash`,
`execution_owner_epoch`, `execution_owner_hash`, `terminal_attempt_hash`,
`proven_recovery_hash`, `cleanup_proof_hash`, `scenario_evidence_hash`,
`evidence_envelope_hash`, `limits_hash`, `facet_id`, `scenario_id`,
`availability`, `production_eligible`, `pricing_status`,
`egress_enforcement`, `telemetry_status`, `replay_support`,
`prompt_eval_count_status`, nullable `prompt_eval_count`,
`eval_count_status`, nullable `eval_count`, `cached_usage_status`,
`cost_status` and `provider_content_present`. `format` is exactly
`worldforge_ollama_private_evidence_artifact_payload_v1`; generation is one;
all values are mechanically copied or derived from the named already-durable
content-free Store projections under the status rules below; and it has no
wall-clock, nonce, scratch identity, raw content or caller field. Its listed
key order and the global canonical serializer deterministically define the
only artifact bytes.

`OllamaPrivateEvidenceArtifactV1` has exactly `format`, `attempt_id`,
`authorization_hash`, `execution_owner_epoch`, `execution_owner_hash`,
`terminal_attempt_hash`, `proven_recovery_hash`, `cleanup_proof_hash`,
`scenario_evidence_hash`, `evidence_envelope_hash`, `limits_hash`, `facet_id`,
`scenario_id`, `availability`, `production_eligible`, `pricing_status`,
`egress_enforcement`, `telemetry_status`, `replay_support`,
`prompt_eval_count_status`, nullable `prompt_eval_count`, `eval_count_status`,
nullable `eval_count`, `cached_usage_status`, `cost_status`,
`provider_content_present`, `artifact_payload_format`, `artifact_size_bytes`,
`artifact_sha256`, `event_id`, `event_payload_hash` and `published_at`.
`format` is exactly `worldforge_ollama_private_evidence_artifact_v1`;
facet/scenario must be one exact pair from the finite catalog below;
availability is only `observed_nonproduction`; `production_eligible` and
`provider_content_present` are false; pricing/cached/cost statuses are
`unavailable`; egress is `not_enforced`; telemetry is
`observed_not_enforced`; and replay is `not_claimed`. Each count status is only
`observed` or `unavailable`; a nonnegative count is present iff its status is
observed. Artifact size is in `1..scenario_scratch_acceptance_max_bytes` from
the exact limits document; `artifact_payload_format` is exactly
`worldforge_ollama_private_evidence_artifact_payload_v1`; and
`artifact_sha256` is both the raw SHA-256 and ordinary canonical-document hash
of the deterministic payload bytes above, never this projection or a provider
body. Both event fields are non-null. Its target body omits them, has domain
ref `attempt_id`, committed-source refs for authorization, owner, terminal
attempt, proven recovery, cleanup proof, scenario evidence, envelope and
limits in declared-key order, and no sibling ref. Publication is
private/non-executable and cannot create a receipt.

Publication re-reads every named source projection in one Store snapshot,
reconstructs the payload deterministically, checks its canonical size/hash
against the projection and atomically `put_if_absent`s the content-addressed
private payload plus the artifact projection in the
`artifact_publication_v1` transaction. ACK loss or a crash after cleanup,
envelope sealing or payload rendering discards volatile bytes; any authorized
retry re-reads the same durable sources, re-renders byte-for-byte and either
returns the identical committed pair or rejects drift. No original main
memory, candidate scratch, staged file or retained artifact byte is an input
to retry. The projection's `artifact_size_bytes` and `artifact_sha256` are the
sole expected size/hash record; they are derived from that same Store snapshot
and committed with the payload, never from staged bytes. A crash before the
atomic transaction leaves neither record; retry deterministically derives both
again. A size/hash mismatch, source revision drift or noncanonical rerender
publishes nothing.

`OllamaDeadlineActionRebootAbandonmentV1` has exactly `format`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`,
`execution_owner_epoch`, `execution_owner_hash`,
`release_projection_hash`, `source_deadline_action_lifecycle_hash`,
`old_linux_boot_id`, `current_linux_boot_id`,
`old_terminal_finalize_deadline_boottime_ns`,
`boot_transition_owner_death_proof_hash`, `recovery_fence_hash`,
`cleanup_proof_hash`, `result_class`,
`action_terminal_reconstructed`, `provider_evidence_present`,
`provider_receipt_present`, `event_id`, `event_payload_hash` and
`committed_at`. `format` is exactly
`worldforge_ollama_deadline_action_reboot_abandonment_v1`; `result_class` is
exactly `abandoned_no_evidence_v1`; and all three booleans are false. Both boot
IDs are canonical Linux UUIDs and must differ. The release is exactly
`fired_before_release|fired_after_release`; the source lifecycle is the
matching immutable old-boot `fire_committed_pending_terminal`; the current
owner is the exact `recovering` owner produced by its `reboot_abort_v1` fence;
the boot-transition proof and cleanup proof both bind those old/new boot IDs;
the cleanup proof in turn binds the exact reboot-abort observation; and cleanup mode is exactly
`reboot_abort_no_evidence_v1` with current-boot zero-resource/sink scrub proof.
`old_terminal_finalize_deadline_boottime_ns` must byte-equal the source
lifecycle scalar, but is retained only as opaque audit data: it is never
compared with, converted into or used to schedule work against the new boot's
`CLOCK_BOOTTIME`.

Both event fields are non-null and use the global Studio formulas. Its target
body omits those fields; its independent domain ref is `attempt_id`; its
committed-source refs, in declared-key order, are authorization, lease,
current execution owner, release, source lifecycle, boot-transition proof,
recovery fence and cleanup proof; and it has no
sibling-body edge. It contains no action result, reconstructed PID1 terminal,
protocol/usage result, provider body, receipt or envelope. It is only the
content-free bridge from an immutable old-boot pending lifecycle to an already
proved current-boot reboot cleanup.

`OllamaEvidenceEligibilityAbandonmentV1` has exactly `format`, `attempt_id`,
`authorization_hash`, nullable `operation_lease_hash`,
`source_attempt_hash`, `source_attempt_state`, nullable
`preexisting_scenario_evidence_hash`, nullable `source_recovery_hash`, nullable
`source_execution_owner_hash`, `stored_linux_boot_id`,
`current_linux_boot_id`, `boot_transition_owner_death_proof_hash`,
`current_boot_absence_kind`, nullable `zero_allocation_journal_hash`, nullable
`reboot_abort_observation_hash`, nullable `current_boot_cleanup_proof_hash`,
`eligibility_generation`, `eligibility_store_revision_before`, `result_class`,
`provider_evidence_present`, `provider_evidence_newly_created`,
`provider_evidence_publication_allowed`, `evidence_envelope_sealing_allowed`,
`private_artifact_publication_allowed`, `event_id`, `event_payload_hash` and
`committed_at`. `format` is exactly
`worldforge_ollama_evidence_eligibility_abandonment_v1`; both boot IDs are
canonical and unequal; generation is one; `result_class` is
`abandoned_reboot_no_evidence_v1`; and the four newly-created/publication
booleans are false. `source_attempt_state` is exactly one of
`consumed_no_resources`, `opening`, `open`, `final_clean`, `failed_clean` or
`failed_cleanup_pending`. `provider_evidence_present` is true if and only if
the exact immutable ScenarioEvidence already existed and its hash is non-null,
whether it remains preterminal or was already consumed by an immutable
`final_clean`; it reports historical private Store state, never new evidence
or publication.

`current_boot_absence_kind` is only `prelease_zero_allocation_v1`,
`lease_reboot_abort_v1` or `post_terminal_reboot_audit_v1`. The prelease form
requires null lease/reboot-abort hashes and a non-null exact zero-allocation
journal. The lease form requires a non-null lease, reboot-abort observation and
cleanup proof, with null zero-allocation journal. The post-terminal form
requires the non-null lease and reboot-abort observation plus exactly one
source-recovery branch: `pending` with its exact
`recovering(reboot_abort_v1)` owner, `proven` with its exact `terminal` owner,
or immutable `failed` with its exact nonterminal owner. Its cleanup-proof field
is null at abandonment: the pending branch must subsequently create the narrow
current-boot cleanup proof below, the proven branch already has an immutable
old-boot cleanup chain, and the failed branch makes no cleanup/unlock claim and
remains locked. All three branches still perform the complete current-boot
absence/sink audit. No form may name an EvidenceEnvelope or private artifact.

Both event fields are non-null under the global formulas. Its target body
omits them; its independent domain ref is `attempt_id`; its committed sources,
in declared-key order, are authorization, optional lease, source attempt,
optional ScenarioEvidence, optional recovery/owner, BootTransition proof,
exactly one absence observation and optional cleanup proof; and it has no
sibling-body edge. The document occupies the unique Store key
`(attempt_id,evidence_envelope_eligibility_v1)` by CAS from canonical absence
to its finalized complete hash. `evidence_envelope_sealed_v1` competes on the
same key and may change absence only to the finalized envelope hash. Thus a
reboot abandonment permanently rejects envelope/artifact publication, while a
previously sealed envelope wins the race and remains immutable: the reboot
returns an `already_envelope_sealed_v1` content-free lookup result and creates
no abandonment or envelope rewrite.

The reboot eligibility relation is exhaustive:

| Durable state when unequal boot is authenticated | Required action |
|---|---|
| `consumed_no_resources` before lease | prove the exact prelease zero-allocation branch, commit eligibility abandonment with `provider_evidence_present=false`, then only failure/recovery cleanup and unlock |
| `opening|open` with no ScenarioEvidence | prove lease reboot-abort cleanup, commit abandonment with `provider_evidence_present=false`, then only `failed_clean|failed_cleanup_pending`, recovery and unlock |
| `open` with preterminal ScenarioEvidence | preserve that ScenarioEvidence, prove reboot-abort cleanup, commit abandonment with `provider_evidence_present=true`, then failure/recovery and unlock; never `final_clean` |
| `final_clean` with `recovery:pending` | preserve both documents, prove current-boot absence, commit abandonment with `provider_evidence_present=true`, then the dedicated recovery/terminal joint transition may bind the reboot cleanup and unlock |
| `final_clean` with `recovery:proven` and `owner:terminal`, but no envelope | perform the post-terminal current-boot audit, commit abandonment with `provider_evidence_present=true`, and do not rewrite attempt, recovery or owner; an already released lock remains released |
| `final_clean` with `recovery:failed`, but no envelope | perform the post-terminal current-boot audit and commit abandonment with `provider_evidence_present=true`; preserve the failed recovery and keep any still-held launch lock closed |
| `failed_clean|failed_cleanup_pending` with `recovery:pending` before envelope | commit abandonment with `provider_evidence_present` equal to ScenarioEvidence-hash presence; cleanup/recovery may reach proven/terminal and unlock, but no evidence publication |
| `failed_clean|failed_cleanup_pending` with `recovery:proven` and `owner:terminal` before envelope | perform the post-terminal current-boot audit and commit abandonment with `provider_evidence_present` equal to ScenarioEvidence-hash presence; do not rewrite attempt, recovery or owner |
| `failed_clean|failed_cleanup_pending` with `recovery:failed` before envelope | perform the post-terminal current-boot audit and commit abandonment with `provider_evidence_present` equal to ScenarioEvidence-hash presence; preserve the failed recovery and keep any still-held launch lock closed |
| EvidenceEnvelope already sealed | create no abandonment, return the exact sealed-envelope lookup and never rewrite the envelope; any still-missing private artifact may use only deterministic Store re-rendering from that envelope |

For the `final_clean|failed_clean`/`recovery:pending` reboot rows only, the
immutable attempt's `cleanup_proof_hash` remains the original same-boot
semantic cleanup proof while the subsequently proven recovery and terminal
owner bind the new reboot-abort cleanup proof. That intentional mismatch is
permitted only with the exact eligibility-abandonment source and can never feed
an envelope.
For either `final_clean|failed_clean` with `recovery:pending`, the narrow
`cleanup_proof_projection_v1` row above is the only post-terminal cleanup-proof
creation path: it leaves the attempt and ScenarioEvidence immutable, repeats
the owner's exact `reboot_abort_v1` fence, the abandonment's authenticated
BootTransition and the same current-boot absence observation, and creates only
`reboot_abort_no_evidence_v1`. The existing recovery/owner joint row may then
prove cleanup and unlock; the abandonment key permanently rejects provider
evidence, envelope and artifact publication.
Every other proven/terminal transaction retains the ordinary equal-cleanup
predicate. A reboot before envelope sealing cannot create ScenarioEvidence,
`final_clean`, an envelope or a private artifact; an already existing
ScenarioEvidence or `final_clean` is historical input, not a PASS or
publication authority. Once an envelope was sealed before reboot, only its
separate deterministic Store-only artifact publication remains eligible.

The existing HandoffAcceptance at ordinal zero is the only target above that is
preauthenticated inbound data: it declares `authentication_hash`, declares no
event fields, and is revalidated under its exact HMAC schema before its body is
frozen. `manager_journal_v1` and `artifact_projection_v1` are intentionally not
source or target tags: no event consumes them, so no abstract schema or alias
exists.

The closed transition relation is the following state-conditioned tuple table.
Each cell is ordered; `A|B` is a closed union, not an omitted predicate. `R#`
means the exact release/lifecycle source/target suffix in the recovery table
immediately below.

| `event_kind` | Ordered source tags and required states | Ordered target tags and required states | Exact cause type |
|---|---|---|---|
| `authorization_consume_joint_v1` | `launch_lock:unlocked, none_v1` | `launch_lock:locked, owner:owned(epoch=1), attempt:consumed_no_resources` | `authorization_v1` |
| `attempt_state_transition_v1` | `attempt:consumed_no_resources` | `attempt:opening` | `control_message_v1(operation_lease_registered_v1)` |
| `attempt_state_transition_v1` | `attempt:opening` | `attempt:open` | `control_message_v1(authenticated_open_handoff_v1)` |
| `pre_manager_registration_joint_v1` | `attempt:opening, owner:owned` | `release:inert_unarmed, lifecycle:not_created, capability_registration:registered_unconsumed_v1` | `authorization_v1` |
| `deadline_credential_source_pending_v1` | `attempt:opening, owner:owned, capability_registration:registered_unconsumed_v1` | `deadline_credential_source:pending_v1` | `control_message_v1(register_before_create_v1)` |
| `deadline_credential_file_observation_sealed_v1` | `attempt:opening, owner:owned, capability_registration:registered_unconsumed_v1, deadline_credential_source:pending_v1` | `deadline_credential_file_observation:created_fsynced_closed_v1` | `control_message_v1(native_credential_writer_completion_v1)` |
| `deadline_credential_source_ready_v1` | `attempt:opening, owner:owned, capability_registration:registered_unconsumed_v1, deadline_credential_source:pending_v1` | `deadline_credential_source:ready_v1` | `credential_file_observation_v1(exact complete hash/revision and created/fsynced/closed inode)` |
| `deadline_action_load_transition_v1` | `attempt:opening, owner:owned, lifecycle:not_created, deadline_credential_source:ready_v1, manager_result:static_action_load_v1/accepted_v1/allocated_v1 with request_hash equal post-capability load recipe, manager_result:static_action_ref_v1/accepted_v1/allocated_v1` | `lifecycle:static_action_loaded_inactive` | `manager_reply_v1(exact static_action_ref_v1 result; preceding LoadUnit result is the immediately prior ordered manager source)` |
| `deadline_action_arm_transition_v1` | `attempt:opening, owner:owned, lifecycle:static_action_loaded_inactive, manager_result:deadline_timer_start_v1/accepted_v1/allocated_v1` | `lifecycle:armed_not_invoked` | `manager_reply_v1(exact timer StartTransientUnit reply)` |
| `candidate_release_transition_v1` | `attempt:opening, owner:owned, release:inert_unarmed, lifecycle:armed_not_invoked` | `release:inert_armed` | `manager_reply_v1(armed timer/property proof)` |
| `candidate_release_transition_v1` | `attempt:open, owner:owned, release:inert_armed, lifecycle:armed_not_invoked` | `release:released` | `control_message_v1(release_admission_v1)` |
| `owner_recovery_joint_v1` | `owner:owned, R0..R9` | `owner_cutoff, recovery_fence:execution_owner_recovery_v1, owner:recovering(epoch+1), matching R targets` | `owner_death_proof_v1|authenticated_revocation_v1` |
| `owner_recovery_takeover_v1` | `owner:recovering, R0|R6|R7|R8|R9|R10|R11|R12` | `owner_cutoff, recovery_fence:recovery_owner_takeover_v1, owner:recovering(epoch+1), matching R targets` | `owner_death_proof_v1|authenticated_revocation_v1` |
| `reboot_owner_recovery_joint_v1` | `owner:owned|recovering, one owner-compatible R0..R12 row` | `recovery_fence:reboot_abort_v1, owner:recovering(epoch+1), matching R targets` | `boot_transition_owner_death_proof_v1` |
| `release_snapshot_issue_v1` | `owner:owned, release:released`, then sequence-zero sentinels or exact previous Acceptance/timing | `release_snapshot:issued` | `control_message_v1(effect_admission_v1)` |
| `release_snapshot_acceptance_record_v1` | `release_snapshot:issued` | `release_snapshot_acceptance:accepted` | `control_message_v1(snapshot_acceptance_v1)` |
| `operation_effect_timing_seal_v1` | `release_snapshot:issued, release_snapshot_acceptance:accepted`, then sequence-zero sentinel or exact predecessor timing | `operation_effect_timing:sealed` | `operation_effect_observation_v1` |
| `deadline_fire_joint_v1` | `owner:owned, release:inert_unarmed|inert_armed|released, lifecycle:armed_not_invoked` | `deadline_tombstone:fired, release:fired_before_release|fired_after_release, lifecycle:fire_committed_pending_terminal` | `deadline_timer_v1(exact capability-bound invocation)` |
| `deadline_action_terminal_v1` | `owner:owned|recovering, release:fired_before_release|fired_after_release, tombstone:fired, lifecycle:fire_committed_pending_terminal, lifecycle/lease/current boot IDs equal` | `lifecycle:invoked_terminal(same owner fields, terminal_finalizer=deadline_action_port_v1)` | `control_message_v1(valid same-boot finalization_only action-port result before finalize deadline)` |
| `deadline_action_terminal_v1` | `owner:recovering, release:fired_before_release|fired_after_release, tombstone:fired, lifecycle:fire_committed_pending_terminal, lifecycle/lease/current boot IDs equal` | `lifecycle:invoked_terminal(same owner fields, terminal_finalizer=recovery_timeout_v1)` | `cleanup_observation_v1(valid same-boot recovery finalizer at/after finalize deadline)` |
| `deadline_action_reboot_abandonment_v1` | `attempt:opening|open|failed_cleanup_pending, owner:recovering(reboot_abort_v1), release:fired_before_release|fired_after_release, lifecycle:fire_committed_pending_terminal(old boot), cleanup_proof:reboot_abort_no_evidence_v1(current boot)` | `deadline_action_reboot_abandonment:abandoned_no_evidence_v1` | `boot_transition_owner_death_proof_v1` |
| `reboot_evidence_eligibility_abandonment_v1` | `attempt:consumed_no_resources|opening|open|final_clean|failed_clean|failed_cleanup_pending, owner:recovering|terminal, exact recovery/ScenarioEvidence sources or none_v1 sentinels from one exhaustive reboot-eligibility row, reboot_abort_observation|zero_allocation_journal, optional cleanup_proof or none_v1 sentinel, eligibility Store key absent` | `evidence_eligibility_abandonment:abandoned_reboot_no_evidence_v1` | `boot_transition_owner_death_proof_v1` |
| `manager_effect_journal_v1` | `attempt:opening|open|failed_cleanup_pending, owner:owned|recovering` | `manager_result:accepted_v1|rejected_v1|unknown_v1|reconciled_existing_v1` | `manager_reply_v1` |
| `custody_handoff_accept_v1` | `attempt:opening|open, owner:owned`, then prior `handoff_chain:generation n` iff `n>0` | `handoff_acceptance:accepted, handoff_chain:generation n+1` | `control_message_v1(valid HandoffAcceptance)` |
| `systemd_terminal_projection_v1` | `attempt:opening|open|failed_cleanup_pending, owner:owned|recovering` | `systemd_terminal:any closed terminal_class` | `manager_reply_v1(retained terminal/property snapshot)` |
| `deadline_credential_cleanup_v1` | `attempt:opening|open|final_clean|failed_clean|failed_cleanup_pending, owner:owned|recovering, capability_registration:registered_unconsumed_v1, none_v1(exact credential-source key absent)|deadline_credential_source:pending_v1|ready_v1, then none_v1(cleanup generation one)|deadline_credential_cleanup:credential_source_clean_v1(exact immediately preceding generation under a fenced later owner epoch)` | `deadline_credential_cleanup:credential_source_clean_v1` | `cleanup_observation_v1(exact normal/failure/recovery/reboot branch and inode/absence fixed point)` |
| `cleanup_proof_projection_v1` | `attempt:consumed_no_resources|opening|open|failed_cleanup_pending, owner:owned|recovering`, plus required terminal source for its mode and exact deadline-credential cleanup proof whenever capability registration exists | `cleanup_proof:one exact closed mode` | `cleanup_observation_v1` |
| `cleanup_proof_projection_v1` | `attempt:final_clean|failed_clean, recovery:pending, owner:recovering(reboot_abort_v1), evidence_eligibility_abandonment:abandoned_reboot_no_evidence_v1, reboot_abort_observation:current_boot_absence_complete, deadline_credential_cleanup:credential_source_clean_v1`; owner fence, abandonment BootTransition/fence/attempt and observation hashes must byte-match | `cleanup_proof:reboot_abort_no_evidence_v1` | `cleanup_observation_v1(exact current-boot absence bound to the authenticated BootTransition and reboot fence)` |
| `scenario_evidence_sealed_v1` | `attempt:open, owner:owned|recovering(same boot only), cleanup_proof:complete, none_v1(exact eligibility Store key absent)` | `scenario_evidence:preterminal` | `cleanup_observation_v1(complete facet, capture and cleanup)` |
| `attempt_terminal_recovery_joint_v1` | `attempt:open, owner:owned|recovering(same boot only), scenario_evidence:preterminal, cleanup_proof:complete, none_v1(exact eligibility Store key absent)` | `attempt:final_clean, recovery:pending` | `cleanup_observation_v1(complete scenario and cleanup)` |
| `attempt_terminal_recovery_joint_v1` | `attempt:consumed_no_resources|opening|open, owner:owned|recovering, excluding every reboot-before-envelope path` | `attempt:failed_clean|failed_cleanup_pending, recovery:pending` | `cleanup_observation_v1(exact failure and cleanup status)` |
| `attempt_terminal_recovery_joint_v1` | `attempt:consumed_no_resources|opening|open, owner:recovering(reboot_abort_v1), evidence_eligibility_abandonment:abandoned_reboot_no_evidence_v1, cleanup_proof:no_candidate_resources_v1|reboot_abort_no_evidence_v1, excluding R6/R7` | `attempt:failed_clean|failed_cleanup_pending, recovery:pending` | `cleanup_observation_v1(exact reboot publication abandonment and cleanup status)` |
| `attempt_terminal_recovery_joint_v1` | `attempt:opening|open, owner:recovering(reboot_abort_v1), release/lifecycle:R6|R7 immutable sources, deadline_action_reboot_abandonment:abandoned_no_evidence_v1, evidence_eligibility_abandonment:abandoned_reboot_no_evidence_v1, cleanup_proof:reboot_abort_no_evidence_v1` | `attempt:failed_clean, recovery:pending` | `cleanup_observation_v1(exact reboot abandonment and cleanup)` |
| `recovery_owner_terminal_joint_v1` | `attempt:final_clean|failed_clean|failed_cleanup_pending, recovery:pending, owner:owned|recovering, excluding every reboot-before-envelope path and reboot R6/R7` | `recovery:proven, owner:terminal` | `cleanup_observation_v1(exact cleanup proof)` |
| `recovery_owner_terminal_joint_v1` | `attempt:final_clean|failed_clean|failed_cleanup_pending, recovery:pending, owner:recovering(reboot_abort_v1), evidence_eligibility_abandonment:abandoned_reboot_no_evidence_v1, cleanup_proof:reboot_abort_no_evidence_v1, release/lifecycle:R0..R5|R8..R12 (R6/R7 explicitly excluded)` | `recovery:proven, owner:terminal` | `cleanup_observation_v1(exact reboot publication abandonment and cleanup proof)` |
| `recovery_owner_terminal_joint_v1` | `attempt:failed_clean|failed_cleanup_pending, recovery:pending, owner:recovering(reboot_abort_v1), deadline_action_reboot_abandonment:abandoned_no_evidence_v1, evidence_eligibility_abandonment:abandoned_reboot_no_evidence_v1, cleanup_proof:reboot_abort_no_evidence_v1` | `recovery:proven, owner:terminal` | `cleanup_observation_v1(exact reboot-abandonment cleanup proof)` |
| `recovery_failed_v1` | `recovery:pending, owner:recovering` | `recovery:failed` | `cleanup_observation_v1(unprovable cleanup)` |
| `evidence_envelope_sealed_v1` | `attempt:final_clean, recovery:proven, owner:terminal, scenario_evidence:terminal_bound_v1(exact hash already bound by sourced final_clean), cleanup_proof:complete, none_v1(exact eligibility Store key absent)` | `evidence_envelope:observed_nonproduction` | `cleanup_observation_v1(forward-only envelope seal and same-key CAS)` |
| `launch_lock_release_v1` | `launch_lock:locked, recovery:proven, owner:terminal, same boot or evidence_envelope:observed_nonproduction` | `launch_lock:unlocked` | `recovery_projection_v1` |
| `launch_lock_release_v1` | `launch_lock:locked, recovery:proven, owner:terminal, evidence_eligibility_abandonment:abandoned_reboot_no_evidence_v1` | `launch_lock:unlocked` | `recovery_projection_v1(reboot cleanup-only unlock)` |
| `artifact_publication_v1` | `attempt:final_clean, recovery:proven, owner:terminal, scenario_evidence:terminal_bound_v1(exact hash already bound by sourced final_clean), evidence_envelope:observed_nonproduction, cleanup_proof:complete, eligibility Store key equals exact envelope hash` | `private_evidence_artifact:observed_nonproduction` | `cleanup_observation_v1(deterministic Store-only payload publication)` |

There is no other singleton release, lifecycle, terminal-attempt or recovery
transition. In particular deadline/fire and pending creation exist only in
`deadline_fire_joint_v1`; recovery fencing/rebinding exists only in one of the
three recovery joint events; every attempt terminal is born only with its
`pending` recovery in `attempt_terminal_recovery_joint_v1`; and a fire-pending
lifecycle reaches invoked-terminal only through one of the two same-boot
bounded finalizer rows. Cross-boot recovery never reaches invoked-terminal and
uses only the explicit reboot-abandonment row. A generic deadline,
recovery-fence or cleanup cause cannot
substitute for those tuple predicates.

The release/lifecycle recovery suffix is exhaustive. "Rebind" means a new
generation with identical state/semantic fields, new exact owner epoch/hash,
the immediate prior complete projection hash and the current recovery-fence
hash. "Source only" means the immutable complete document is re-read and
included in `source_refs`, with no target of that tag.

| Pattern | Exact committed current pair | Eligible recovery owner state/path | Ordered recovery-event sources | Ordered targets after the new owner target | Completion path |
|---|---|---|---|---|---|
| R0 | no release and no lifecycle registered | owned initial/reboot; recovering takeover/reboot | none | none | zero-resource cleanup |
| R1 | `inert_unarmed / not_created` | owned initial/reboot | release, lifecycle | `release:recovery_fenced`, `lifecycle:not_created` rebound | cleanup after exact absence |
| R2 | `inert_unarmed / static_action_loaded_inactive` | owned initial/reboot | release, lifecycle | `release:recovery_fenced`, lifecycle same-state rebound | ordered Unref/object-absence cleanup |
| R3 | `inert_unarmed / armed_not_invoked` | owned initial/reboot | release, lifecycle | `release:recovery_fenced`, lifecycle same-state rebound | timer/action closure then cleanup |
| R4 | `inert_armed / armed_not_invoked` | owned initial/reboot | release, lifecycle | `release:recovery_fenced`, lifecycle same-state rebound | timer/action closure then cleanup |
| R5 | `released / armed_not_invoked` | owned initial/reboot | release, lifecycle | `release:recovery_fenced`, lifecycle same-state rebound | indeterminate-effect classification then cleanup |
| R6 | `fired_before_release / fire_committed_pending_terminal` | owned initial/same-boot recovery; recovering same-boot takeover; owned or recovering reboot-abort | release, lifecycle | none; both source only | same boot: bounded finalization then R8; reboot: current-boot cleanup then abandonment, never R8 |
| R7 | `fired_after_release / fire_committed_pending_terminal` | owned initial/same-boot recovery; recovering same-boot takeover; owned or recovering reboot-abort | release, lifecycle | none; both source only | same boot: bounded finalization then R9; reboot: current-boot cleanup then abandonment, never R9 |
| R8 | `fired_before_release / invoked_terminal` | owned initial/reboot; recovering takeover/reboot | release, lifecycle | none; both source only | retained terminal/object cleanup |
| R9 | `fired_after_release / invoked_terminal` | owned initial/reboot; recovering takeover/reboot | release, lifecycle | none; both source only | retained terminal/object cleanup |
| R10 | `recovery_fenced / not_created` | recovering takeover/reboot | release, lifecycle | lifecycle same-state rebound only | zero-object cleanup |
| R11 | `recovery_fenced / static_action_loaded_inactive` | recovering takeover/reboot | release, lifecycle | lifecycle same-state rebound only | ordered Unref/object-absence cleanup |
| R12 | `recovery_fenced / armed_not_invoked` | recovering takeover/reboot | release, lifecycle | lifecycle same-state rebound only | timer/action closure then cleanup |

No other cross-product is reachable: fire atomically creates R6/R7, its bounded
finalizer creates R8/R9, and a recovery joint atomically creates R10/R11/R12
from R1..R5 as applicable. Fired and recovery-fenced releases and an
`invoked_terminal` lifecycle are immutable sources. The pending lifecycle in
R6/R7 also remains an old-epoch source. On the same boot only, recovery records
the one `finalization_only` exception without rebinding it, compares clocks
only within that boot, accepts exactly one action-port finalizer before the
frozen deadline or one recovery finalizer at or after it, and reaches R8/R9
while preserving the original owner fields. After a boot transition, the old
deadline belongs to a destroyed clock domain: recovery neither waits for nor
compares it, never writes `invoked_terminal`, and never reconstructs an
action/PID1 result. It proves the exact current-boot
`reboot_abort_no_evidence_v1` fixed point, then creates only the immutable
reboot-abandonment projection from the unchanged R6/R7 pair. That projection
is the mandatory source for the failure-terminal/proven-recovery/terminal-owner
chain and can never support `final_clean`, an envelope or provider evidence.
Thus every valid stored pair has one cleanup path; environmental proof loss
still correctly leaves recovery failed and the Studio lock closed rather than
inventing state.

The following is the complete target-body/finalization topology. `-` means the
body has no same-event sibling edge. Each `field -> ordinal` entry is present in
that body's `sibling_body_refs`; finalization fills that declared target field
with the earlier ordinal's **complete** hash only after the event exists. A
recovery suffix is legal only for the exact R-pattern named in that topology
row: R1--R5 create both release and lifecycle targets, R10--R12 create only a
lifecycle target, and R0/R6--R9 create neither.

| Event kind | Body/finalization order and exact same-event relation fields |
|---|---|
| `authorization_consume_joint_v1` | `0 launch_lock_projection_v1 [-]`; `1 execution_owner_projection_v1 [-]`; `2 attempt_projection_v1 [execution_owner_hash -> 1]` |
| `attempt_state_transition_v1` | `0 attempt_projection_v1 [-]` |
| `pre_manager_registration_joint_v1` | `0 candidate_release_projection_v1 [-]`; `1 deadline_action_lifecycle_projection_v1 [-]`; `2 deadline_action_capability_registration_v1 [-]` |
| `deadline_credential_source_pending_v1` | `0 deadline_credential_source_v1 [-]` |
| `deadline_credential_file_observation_sealed_v1` | `0 deadline_credential_file_observation_v1 [-]` |
| `deadline_credential_source_ready_v1` | `0 deadline_credential_source_v1 [-]` |
| `deadline_action_load_transition_v1` | `0 deadline_action_lifecycle_projection_v1 [-]` |
| `deadline_action_arm_transition_v1` | `0 deadline_action_lifecycle_projection_v1 [-]` |
| `owner_recovery_joint_v1` | `0 owner_cutoff_v1 [-]`; `1 recovery_fence_v1 [owner_cutoff_hash -> 0]`; `2 execution_owner_projection_v1 [owner_cutoff_hash -> 0, recovery_fence_hash -> 1]`; R1..R5 only: `3 candidate_release_projection_v1 [recovery_fence_hash -> 1, execution_owner_hash -> 2]`; `4 deadline_action_lifecycle_projection_v1 [execution_owner_hash -> 2]`; R0/R6..R9: no suffix |
| `owner_recovery_takeover_v1` | `0 owner_cutoff_v1 [-]`; `1 recovery_fence_v1 [owner_cutoff_hash -> 0]`; `2 execution_owner_projection_v1 [owner_cutoff_hash -> 0, recovery_fence_hash -> 1]`; R10..R12 only: `3 deadline_action_lifecycle_projection_v1 [execution_owner_hash -> 2]`; R0/R6..R9: no suffix |
| `reboot_owner_recovery_joint_v1` | `0 recovery_fence_v1 [-]`; `1 execution_owner_projection_v1 [recovery_fence_hash -> 0]`; R1..R5: `2 candidate_release_projection_v1 [recovery_fence_hash -> 0, execution_owner_hash -> 1]`; `3 deadline_action_lifecycle_projection_v1 [execution_owner_hash -> 1]`; R10..R12: `2 deadline_action_lifecycle_projection_v1 [execution_owner_hash -> 1]`; R0/R6..R9: no suffix |
| `candidate_release_transition_v1` | `0 candidate_release_projection_v1 [-]` |
| `release_snapshot_issue_v1` | `0 release_snapshot_v1 [-]` |
| `release_snapshot_acceptance_record_v1` | `0 release_snapshot_acceptance_v1 [-]` |
| `operation_effect_timing_seal_v1` | `0 operation_effect_timing_v1 [-]` |
| `deadline_fire_joint_v1` | `0 deadline_tombstone_v1 [-]`; `1 candidate_release_projection_v1 [deadline_tombstone_hash -> 0]`; `2 deadline_action_lifecycle_projection_v1 [deadline_tombstone_hash -> 0]` |
| `deadline_action_terminal_v1` | `0 deadline_action_lifecycle_projection_v1 [-]` |
| `deadline_action_reboot_abandonment_v1` | `0 deadline_action_reboot_abandonment_v1 [-]` |
| `reboot_evidence_eligibility_abandonment_v1` | `0 evidence_eligibility_abandonment_v1 [-]` |
| `manager_effect_journal_v1` | `0 manager_effect_result_v1 [-]` |
| `custody_handoff_accept_v1` | `0 handoff_acceptance_v1 [-]`; `1 handoff_chain_v1 [last_acceptance_hash -> 0]` |
| `systemd_terminal_projection_v1` | `0 systemd_terminal_projection_v1 [-]` |
| `deadline_credential_cleanup_v1` | `0 deadline_credential_cleanup_proof_v1 [-]` |
| `cleanup_proof_projection_v1` | `0 cleanup_proof_v1 [-]` |
| `scenario_evidence_sealed_v1` | `0 scenario_evidence_v1 [-]` |
| `attempt_terminal_recovery_joint_v1` | `0 attempt_projection_v1 [-]`; `1 recovery_projection_v1 [terminal_attempt_hash -> 0]` |
| `recovery_owner_terminal_joint_v1` | `0 recovery_projection_v1 [-]`; `1 execution_owner_projection_v1 [recovery_projection_hash -> 0]` |
| `recovery_failed_v1` | `0 recovery_projection_v1 [-]` |
| `evidence_envelope_sealed_v1` | `0 evidence_envelope_v1 [-]` |
| `launch_lock_release_v1` | `0 launch_lock_projection_v1 [-]` |
| `artifact_publication_v1` | `0 private_evidence_artifact_v1 [-]` |

Each pipe-delimited cause cell means exactly one of those tags. Recovery cause
is always the already committed underlying death, authenticated-revocation or
BootTransition proof; an OwnerCutoff or RecoveryFence being created by that
same transaction can never be its cause. Initial same-boot recovery first
freezes OwnerCutoff, then RecoveryFence naming that cutoff, then the owner and
the exact R1--R5 release/lifecycle targets, or no such targets for R0/R6--R9.
A takeover uses the same cutoff/fence/owner order and may rebind only the
R10--R12 lifecycle; its R0/R6--R9 source pairs remain immutable. Reboot has no
cutoff, freezes RecoveryFence then owner, creates release plus lifecycle targets
for R1--R5, only a lifecycle target for R10--R12, and no pair target for
R0/R6--R9. For reboot R6/R7, only after the separate current-boot reboot-abort
cleanup proof commits may the one-target abandonment event bind that proof and
the unchanged old-boot pair; it has no sibling edge and no lifecycle target.
Every reboot before envelope sealing also commits the distinct one-target
eligibility abandonment after its required current-boot absence observation;
that target has no sibling edge and atomically wins the same unique-key CAS
that envelope sealing would otherwise consume. Neither document hashes that
Store key or the competing consumer, so the graph remains acyclic.
StudioStore reads
`store_revision_before`, derives its checked one-step successor before building
any target, and places that expected value in RecoveryFence `store_revision`
and every target ref; CAS either commits the whole ordered graph at that exact
revision or none. Thus Store revision is an input to the target bodies, never a
result hashed back from a completed target.
OwnerCutoff and RecoveryFence declare no event or authentication fields, but
they still use the exact target-body wrapper. A same-event RecoveryFence body
names only the prior OwnerCutoff body hash; its complete document receives the
finalized OwnerCutoff complete hash afterward. The new owner/gate/lifecycle
targets follow the same ordinal-only rule and are finalized only after the
event as defined above.

For `release_snapshot_issue_v1`, the two trailing sequence-0 sentinels mean
"no previous snapshot Acceptance" and "no previous timing" in that exact
order. At sequence greater than zero they are the immediately preceding
SnapshotAcceptance and its already committed timing. For
`operation_effect_timing_seal_v1`, the trailing sentinel at sequence zero means
"no predecessor timing"; later seals name the immediately preceding timing.
Every named current snapshot, current Acceptance and predecessor is re-read at
its committed Store revision. No inferred hash or in-memory chain state may
substitute.

No other event kind, source/target order, body topology or optional suffix is
valid. A joint transaction computes every event-free target body in table
order, one event payload second, and all complete targets in the same order
last, then CASes them atomically. A mechanical graph check must prove that every
body edge points to a lower ordinal and that no body/event preimage contains a
same-event complete target, `event_id`, `event_payload_hash` or target HMAC.
`attempt_revision_after` is
the target attempt revision when the event writes one and otherwise equals
`attempt_revision_before`; each value is respectively zero or the exact source/
target attempt projection generation, and consume alone uses `0 -> 1`.
`transaction_id`, `event_payload_hash` and the resulting `event_id` must match
the three formulas above byte for byte. An ACK-loss retry with
the same transaction/event bytes returns every recorded target without a new
effect; changed bytes or a missing source fails. System-PID1 create, custody
handoff, cleanup kill, attempt CAS and artifact publication all use this exact
event identity and lookup-before-effect rule; no implementation may invent a
source projection from a target, cause label or caller assertion.

The consume event re-reads the unique current unlocked launch-lock projection,
uses `none_v1` only for the absence of a prior attempt/owner, then atomically
publishes locked-to-this-attempt, owner epoch 1 and `consumed_no_resources`.
The lock target never references either same-event sibling. Each custody-handoff
event first commits the independently authenticated inbound Acceptance target,
then commits the chain head whose only same-event relation is that ordinal-zero
complete Acceptance hash; later events additionally re-read the prior complete
chain. These are the only creation paths for launch-lock and handoff-chain
projections.

The failed effect classifications remain only `clean_no_launch`,
`clean_before_send`, `indeterminate_after_possible_send` and
`indeterminate_cleanup_unproven`; failure codes are closed code-owned tokens.
Every hash follows the scoped content/domain/raw/HMAC rules above, each nullable field is present as
canonical JSON `null`, wall-clock fields use the authorization's canonical UTC
representation, and explicitly named boottime/monotonic fields are checked
nonnegative integer nanoseconds/microseconds in the document's bound Linux
boot. The reboot-abandonment document's sole `old_*_boottime_ns` scalar remains
bound to its explicitly named old boot and is never compared with the current
boot. Only the construction-owned main authority writes these
separate trusted StudioStore sinks, except that the exact deadline-action
Store port below may execute only its capability-bound fire CAS and terminal
projection. Their schemas cannot carry prompt, request,
response, output, provider log, raw capture or other provider content;
candidate/lease processes and the custody broker have no StudioStore API,
database path, SQL, cursor or generic key/value access.

Attempt terminals never mutate. Cleanup release uses a separate append-only
`OllamaEvidenceRecoveryProjection` with exactly `format`, `recovery_id`,
`recovery_nonce_hash`, `attempt_id`, `terminal_attempt_hash`, nullable
`operation_lease_hash`, `execution_owner_epoch`, `execution_owner_hash`, `state`,
positive `generation`, nullable `prior_recovery_hash`, `event_id`, `event_payload_hash`,
`observation_hash`, nullable
`cleanup_proof_mode`, nullable `cleanup_proof_hash` and `committed_at`. `format` is
`worldforge_ollama_evidence_recovery_v1`; state is only `pending`, `proven` or
`failed`, and its only transition is `pending -> proven|failed` under the same
canonical hash, event-id and CAS rules. Every terminal-attempt transaction also
creates its exact `pending` recovery record. `pending` has canonical-null
`cleanup_proof_hash`; `proven` requires a non-null exact proof; `failed` binds
the last observation and cannot later become `proven`. The projection's own
`event_id` and `event_payload_hash`, together with that event's explicit
ordered source and cause references, are the complete transition lineage.

There is exactly one terminal/proven publication operation. Given the immutable
terminal-attempt hash, expected `pending` recovery hash/generation, expected
current `owned|recovering` owner hash/epoch/generation and exact cleanup proof,
StudioStore first computes the event-free `proven` recovery body. That body
names the pre-terminal owner only. It then computes the `terminal` owner body
whose table edge names that recovery **body**, not its not-yet-existing complete
hash, and whose `cleanup_proof_hash` names the same independently committed
proof. After constructing the joint event it finalizes the recovery, fills the
owner's `recovery_projection_hash` with that finalized recovery complete hash,
then independently finalizes the owner. One database transaction atomically
CASes `pending -> proven` **and** `owned|recovering -> terminal`; neither write
may exist without the other, and there is no later owner-terminal or
recovery-proven ordering. The recovery never points to the terminal owner and
neither body names a same-event complete target, so the hashes are acyclic. ACK
loss looks up and returns the same exact pair;
changed bytes or either stale expected generation rejects both.

The recovery and terminal-owner bodies always bind the same cleanup proof. In
the sole `final_clean|failed_clean`/`recovery:pending` reboot-before-envelope
rows, that new
proof is the current-boot `reboot_abort_no_evidence_v1` proof while the
immutable terminal attempt continues to name its earlier same-boot cleanup;
the transaction must also consume the exact eligibility-abandonment source.
Every other row requires the terminal attempt, recovery and terminal owner to
name one byte-identical cleanup proof. The exceptional pair can unlock after
current-boot cleanup, but the occupied abandonment key makes an envelope or
artifact mechanically impossible.

Only that jointly committed `proven`/`terminal` pair can release the
Studio-wide launch lock. `pending`, `failed`, a nonterminal owner, a mismatched
pair or an unacknowledged transaction keeps the lock closed.

Release is one exact StudioStore CAS:
`(lock_owner_attempt_id, launch_lock_generation, recovery_hash,
expected_locked=true) -> (lock_owner_attempt_id=null,
launch_lock_generation+1, last_recovery_hash=recovery_hash, locked=false)`.
The owner must equal the recovery's attempt and the recovery must be `proven`.
The exact execution-owner projection must also be `terminal` at the recovery's
epoch and bind that recovery/cleanup hash.
An ACK-loss retry looks up that exact before/after generation and returns the
same result; a stale generation, different owner/recovery hash or already reused
generation cannot unlock another attempt.

The separate content-free `OllamaEvidenceSystemdTerminalProjection` has exactly
`format`, `attempt_id`, `authorization_hash`, `operation_lease_hash`,
`execution_owner_epoch`, `execution_owner_hash`,
`systemd_manager_identity_hash`, `systemd_unit_name`,
`systemd_unit_object_path`, nullable `systemd_invocation_id`,
`systemd_deadline_timer_name`, nullable `deadline_timer_invocation_id`,
`systemd_deadline_action_name`, nullable `deadline_action_invocation_id`,
nullable `deadline_timer_properties_hash`, nullable
`timer_operation_retention_hash`,
nullable `unit_gc_retention_observation_hash`, `deadline_action_lifecycle_hash`,
`candidate_release_projection_hash`, nullable
`deadline_tombstone_hash`,
`terminal_class`, `main_pid`, `exec_main_code`, `exec_main_status`, `result`,
`active_state`, `sub_state`, `terminal_properties_hash`,
`observed_boottime_ns`, positive `generation`, nullable `prior_terminal_hash`,
`event_id`, `event_payload_hash` and `committed_at`. `format` is exactly
`worldforge_ollama_evidence_systemd_terminal_v1`; `terminal_class` is only
`semantic_sentinel_125`, `main_loss_sentinel_124`,
`custody_failure_sentinel_126`, `crash_exit`, `crash_signal`, `watchdog`,
`timeout`, `deadline_action` or `manager_failure`. The property hash covers the
authenticated PID1 D-Bus values, their types and the retained invocation IDs;
nullable values remain explicit canonical JSON `null` rather than being
inferred. The projection uses the same bounded serializer, event identity and
CAS/ACK-loss rules as attempt projections. The exact deadline-action lifecycle
`not_created` requires the timer invocation, timer-properties and
timer-operation-retention hashes null;
`static_action_loaded_inactive` also requires those timer fields null while its
static-install/load/action-property hashes are non-null;
`armed_not_invoked|fire_committed_pending_terminal|invoked_terminal` requires
them non-null and mutually bound. An operation created before the timer
transaction may still use `live_main_pidfds_v1` or, after broker death/incomplete
candidate handoff while main remains live,
`same_boot_retained_systemd_domain_v1`; after main loss it may use
`offline_systemd_v1` only when the operation itself is the exact retained
failed `main_loss_sentinel_124` unit under `CollectMode=inactive`, as proved by
the pre-timer main-loss contract below. No timer relationship is invented for
that path. A `fire_committed_pending_terminal` lifecycle is an intermediate
observation only and cannot be the lifecycle hash in this terminal projection
or any cleanup proof. On the same boot it must first reach `invoked_terminal`
under the exact bounded finalization rules. After a boot transition it never
does: reboot cleanup keeps `deadline_action_lifecycle_hash` null and proves
only current-boot absence, then the separate reboot-abandonment projection
binds that proof to the unchanged old-boot pending lifecycle.
The exact deadline-action lifecycle
snapshot and this terminal projection are both committed durably while the
operation and every timer/action object that exists remain loaded, with exact
absence snapshots for `not_created`, and before
`ResetFailedUnit`, any retention-releasing `UnrefUnit`, timer/action reset or
any operation that permits unit collection. The sole earlier Unref is the
journalled static-action reference handoff after the armed timer dependency is
proven; it cannot remove the last retention source. An ACK-loss retry re-reads the same retained failed unit and
looks up the exact projection; it neither resets nor creates a replacement.
This projection carries no scenario or provider content and its exact hash is a
required input to cleanup proof.

This `StudioHumanDecisionAuthority`, durable Director contract, attempt/recovery
Store and launch lock do not yet exist. Therefore evidence execution remains
unavailable; no weaker approval or in-memory state can activate it.

### Crash-safe custody prerequisite

The frozen static `OllamaEvidenceCustodyPolicyV1` has exactly `format`, `mechanism`,
`main_authority_hash`, `owner_liveness_observer_policy_hash`,
`systemd_policy_hash`, `broker_recipe_policy_hash`,
`native_single_thread_broker_policy_hash`,
`broker_ready_policy_hash`, `operation_stdin_fd_policy_hash`,
`handoff_policy_hash`, `operation_lease_policy_hash`,
`outer_unit_derivation_policy_hash`,
`candidate_subgroup_derivation_policy_hash`, `main_loss_lease_policy_hash`,
`fork_safe_launcher_policy_hash`, `key_vault_policy_hash`,
`custody_proof_policy_hash`, `deadline_timer_derivation_policy_hash`,
`deadline_action_derivation_policy_hash`, `deadline_action_static_install_policy_hash`,
`deadline_action_store_policy_hash`,
`candidate_release_policy_hash`,
`deadline_tombstone_policy_hash`, `terminal_retention_policy_hash`,
`lease_recovery_policy_hash`, `device_cleanup_policy_hash`,
`limits_hash`, `scratch_parent_hash`, `cleanup_policy_hash`,
`timeout_stop_usec`. `format` is
`worldforge_ollama_evidence_custody_policy_v1`; `mechanism` is the sole literal
`systemd_pid1_transient_operation_service_v1`; the maximum duration comes only
from its exact `limits_hash` and is not an absolute timestamp.
Every hash is a completed construction-time policy/identity reference. The
document contains no attempt, authorization, lease ID, unit name/object path,
candidate subgroup/scratch identity or final broker/unit/subgroup/timer/action
recipe hash. Authorization may bind only this static document, never an
operation-local recipe.
There is no alternative cgroup manager or user-session manager contract.

Before either lease or release document exists, main generates independent
32-byte kernel-CSPRNG `release_gate_nonce` and
`deadline_tombstone_nonce` values. It hashes the first raw nonce, fixes
`release_gate_id_generation=1` and `production_eligible=false`, and computes
`release_gate_id` only by the byte formula and golden vector above. Each nonce
is registered by exact authority
identity and never supplied by a caller; `release_gate_nonce_hash` is lowercase
SHA-256 of the 32 raw gate-nonce bytes and
`deadline_tombstone_nonce_hash` is lowercase SHA-256 of the 32 raw independent
tombstone-nonce bytes. The recovery Store namespace is independently keyed by
attempt/authorization and is not the tombstone key.

After authorization and the independent `attempt_id` exist, but before any
lease document, recipe, scratch, manager effect or other resource, main creates
a third independent 32-byte kernel-CSPRNG `lease_nonce`, registers its raw-byte
hash and fixes `lease_id_generation=1` plus
`production_eligible=false`. It derives `lease_id` solely by the exact formula
above from attempt, authorization and that nonce hash. The ID contains no
custody policy, proof, owner, clock, unit, subgroup, recipe or lease-document
hash. ACK loss looks up the registered `(attempt_id, authorization_hash,
lease_nonce_hash, generation, production_eligible, lease_id)` tuple and never
generates replacement entropy.

After the resource-free boot/open/deadline samples exist and before the lease
is frozen, main constructs `DeadlineTombstoneKeyDocumentV1` with exactly
`format`, `attempt_id`, `authorization_hash`, `release_gate_id`,
`execution_owner_epoch`, `deadline_boottime_ns` and
`deadline_tombstone_nonce_hash`. `format` is exactly
`worldforge_ollama_deadline_tombstone_key_document_v1`. Its
`deadline_tombstone_key_hash` is the exact domain-separated formula above. The
document contains no lease, release-projection, tombstone, lifecycle,
capability, timer/action invocation or other consumer hash. The lease,
candidate-release projection, deadline-action lifecycle, deadline tombstone
and deadline-action capability all bind this one key-document hash; none is
hashed back into it. These resource-free one-way values make the dependency
graph acyclic.

With the authorization, attempt, registered `lease_id`, static custody policy,
static derivation policies, owner epoch, clock/deadline samples and tombstone
key fixed, main derives the final broker, outer-operation unit,
candidate-subgroup, deadline-timer and static-action-instance recipe documents.
Each final recipe binds `authorization_hash`, `attempt_id`, `lease_id` and its
static policy one-way; none is present in or hashed by the authorization,
custody policy or lease-ID preimage. Only after all five recipe hashes exist may
main construct the OperationLease, which binds them. Thus the forward DAG is
`authorization -> attempt/lease nonce -> lease_id -> final recipes ->
OperationLease -> opening`; no edge points back to authorization or lease ID.

The mandatory outer `OllamaEvidenceOperationLease` contains both the broker and
a separately killable candidate subgroup. Its frozen type has exactly `format`,
`lease_id`, `lease_nonce_hash`, `lease_id_generation`, `production_eligible`,
`attempt_id`, `authorization_hash`, `custody_policy_hash`,
`candidate_profile_hash`, `candidate_recipe_policy_hash`,
`operation_lease_policy_hash`, `systemd_policy_hash`,
`execution_owner_epoch`, `execution_owner_hash`, `linux_boot_id`,
`opened_boottime_ns`, `deadline_boottime_ns`, `timer_on_boot_usec`,
`deadline_guard_usec`, `max_enforcement_latency_usec`, `timer_accuracy_usec`,
`timer_clock_conversion_tolerance_ns`, `timer_clock_uncertainty_limit_ns`,
`timer_safety_margin_ns`, `deadline_action_terminal_finalize_timeout_ns`,
`timer_randomized_delay_usec`, `timer_wake_system`,
`timer_remain_after_elapse`, `release_gate_id`,
`candidate_release_policy_hash`,
`deadline_tombstone_key_hash`,
`custody_proof_hash`, `systemd_manager_identity_hash`, `systemd_unit_name`,
`systemd_unit_object_path`, `systemd_deadline_timer_name`,
`systemd_deadline_timer_object_path`, `systemd_deadline_action_name`,
`systemd_deadline_action_object_path`, `broker_recipe_hash`, `outer_unit_recipe_hash`,
`operation_stdin_fd_policy_hash`, `broker_ready_policy_hash`,
`deadline_timer_recipe_hash`, `deadline_action_recipe_hash`,
`deadline_action_static_install_hash`,
`deadline_action_store_policy_hash`,
`candidate_subgroup_recipe_hash`, `main_loss_lease_policy_hash`,
`native_single_thread_broker_policy_hash`, `fork_safe_launcher_policy_hash`,
`key_vault_policy_hash` and
`limits_hash`. `format` is exactly
`worldforge_ollama_evidence_operation_lease_v1`. The boot ID is the canonical
lowercase Linux UUID;
`lease_nonce_hash` is the registered raw nonce digest,
`lease_id_generation=1`, and `production_eligible=false`;
clock values are nonnegative integer nanoseconds from `CLOCK_BOOTTIME`;
`deadline_boottime_ns = opened_boottime_ns +
LimitsV1.maximum_operation_duration_ns` uses checked integer addition. This is
the logical admission cutoff within that exact boot, not a
hard-real-time claim. `timer_on_boot_usec` is
`max(0, floor(deadline_boottime_ns / 1000) - deadline_guard_usec)`;
`deadline_guard_usec` must exceed the bound timer accuracy plus the exact
live-observed maximum action-to-domain-empty latency and its code-owned safety
margin. The frozen booleans are `timer_wake_system=true` and
`timer_remain_after_elapse=true`; `timer_randomized_delay_usec` is zero.
The derived trigger must still be strictly later than current
`CLOCK_BOOTTIME` when `opening` is committed and when the timer is armed;
otherwise the inert unit is closed without candidate release.

`lease_id` is exactly the lowercase result of the fixed-width
`worldforge-ollama-operation-lease-id-v1` formula and golden vector above. The
OperationLease revalidates that ID against its attempt, authorization, nonce
hash, generation and immutable false production flag; none of its remaining
fields or recipe hashes enters the ID preimage.
The exact deterministic unit name is
`worldforge-ollama-evidence-<lease_id>.service`; its system-PID1 D-Bus object path
is derived by systemd's unit-name escaping and persisted exactly. The matching
deadline units are
`worldforge-ollama-evidence-deadline@<lease_id>.timer` and
the installed-template instance
`worldforge-ollama-evidence-deadline@<lease_id>.service`, with their escaped
D-Bus object paths persisted exactly. Reading boot ID/boottime and
deriving/registering this frozen object are resource-free; no manager
reservation, unit/timer creation or other manager effect occurs before the
`opening` CAS.

The content-free `OllamaEvidenceCandidateReleaseV1` has exactly `format`,
`release_gate_id`, `release_gate_nonce_hash`, `release_gate_id_generation`,
`production_eligible`, `attempt_id`,
`authorization_hash`, `operation_lease_hash`, `execution_owner_epoch`,
`execution_owner_hash`, `state`, positive `generation`,
nullable `prior_release_hash`, `event_id`, `event_payload_hash`,
`deadline_tombstone_key_hash`, nullable `deadline_tombstone_hash`, nullable
`released_boottime_ns`, nullable `recovery_fence_hash`, nullable
`recovery_fence_boottime_ns` and `committed_at`. `format` is exactly
`worldforge_ollama_evidence_candidate_release_v1`; state is only
`inert_unarmed`, `inert_armed`, `released`, `fired_before_release` or
`fired_after_release`, plus `recovery_fenced`. The exact transitions are
`inert_unarmed -> inert_armed`, `inert_armed -> released`,
`inert_unarmed|inert_armed -> fired_before_release`, and
`released -> fired_after_release`; the first two occur only through
`candidate_release_transition_v1`, the fire transitions only through
`deadline_fire_joint_v1`, and a mutable non-fired state changes to
`recovery_fenced` only as the R1--R5 release target of an owner/reboot recovery
joint event. Fired states and a previously recovery-fenced state remain
immutable sources during recovery. Fired and recovery-fenced states are
terminal. It uses the same
canonical serializer, event identity, CAS and ACK-loss rules as attempt state.
The `inert_unarmed -> inert_armed` transaction re-reads, in order, the exact
current `opening` attempt, its exact `owned` execution owner, the current
`inert_unarmed` release and matching `armed_not_invoked` lifecycle. Their
attempt/authorization/lease/owner epoch and complete owner hash must all agree.
A terminal or non-opening attempt, `recovering`/`terminal` owner, stale owner
epoch/hash, fired/recovery-fenced release, lifecycle drift or any intervening
CAS winner rejects the transition; a timer/property proof alone is never
release authority.
`release_gate_id_generation` is exactly one, `production_eligible` exactly
false, and the ID must reproduce the fixed formula/vector from its attempt,
authorization and registered nonce hash.
The projection requires the identity-registered nonce whose hash it names and
the exact lease whose stable `release_gate_id` matches; the lease never binds a
release-projection hash. `open` binds the exact `inert_armed` projection only
after both documents exist.

The broker never reads StudioStore. For each candidate-side effect, main issues
one frozen `OllamaEvidenceReleaseGateSnapshotV1` with exactly `format`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`,
`execution_owner_epoch`, `execution_owner_hash`, `release_gate_id`,
`release_revision`, `release_projection_hash`, `release_state`, nullable
`deadline_tombstone_hash`, nullable `tombstone_fired_boottime_ns`, nullable
`recovery_fence_hash`, nullable `recovery_fence_boottime_ns`, `effect_kind`,
`issued_boottime_ns`, `not_before_boottime_ns`, `expires_boottime_ns`,
`sequence`, `prior_snapshot_hash`, `predecessor_effect_timing_hash`,
`issuer_principal`, `receiver_principal`, `key_id` and
`authentication_hash`. `format` is exactly
`worldforge_ollama_release_gate_snapshot_v1`; principals are the sole ordered
pair `studio_main_v1 -> ollama_evidence_broker_v1`; and `effect_kind` is only
`config_disclosure`, `fork_exec`, `listener_effect` or `request_send`.
`release_revision` is exactly the positive `generation` of
`release_projection_hash`; no independent counter is accepted.

The snapshot is issued from one atomic Store transaction that reads and CASes
the current owner hash/epoch/state, release projection/revision, tombstone and
recovery fence, next snapshot sequence/hash-chain record and the exact
sequence-specific prior Acceptance/timing source pair or its two explicit
`none_v1` sentinels. It commits the `release_snapshot_issue_v1` event and target
atomically. Issuance requires
owner state `owned`, release state `released`, no tombstone or recovery fence,
the same boot, and a positive validity interval no longer than the exact bound
in `limits_hash`, with
`not_before_boottime_ns <= issued_boottime_ns < expires_boottime_ns <=
deadline_boottime_ns`. Sequence zero names 64 zeroes; each later snapshot
names the complete prior snapshot hash. Sequence zero has
`predecessor_effect_timing_hash` equal to 64 zeroes; every later snapshot names
the exact already sealed prior timing document. ACK loss returns the exact
recorded bytes; changed effect, revision, sequence or fields are rejected.

There is no bootstrap batch. Main issues snapshots strictly one at a time in
the order `config_disclosure`, `fork_exec`, `listener_effect`, `request_send`.
It may issue the next snapshot only after it has verified the prior Acceptance,
received and durably sealed the complete prior operation-effect timing through
`operation_effect_timing_seal_v1`, and
atomically re-read the current owner/gate/tombstone/cutoff view. The prior
timing's `effect_return_boottime_ns` must be no later than the next snapshot's
`issued_boottime_ns`, and its hash must equal
`predecessor_effect_timing_hash`. A vendor bind that races ahead of the
sequential `listener_effect` admission is observed drift and makes the scenario
non-evidence; it is never excused by preissuing authority. `request_send`
additionally follows causal peer proof.

After the broker identity is proven and the handoff key exists, both authorities
derive the 32-byte directional snapshot key as HMAC-SHA256 of that raw handoff
key over ASCII `worldforge-ollama-release-snapshot-key-v1`, one NUL byte each,
the attempt ID, lease hash and decimal owner epoch. `key_id` is SHA-256 over
those 32 raw derived bytes. `authentication_hash` is HMAC-SHA256 with that key
over ASCII `worldforge-ollama-release-gate-snapshot-v1`, one NUL byte and the
canonical snapshot with only `authentication_hash` omitted. The derived key is
confined to the exact main/broker key-vault mappings defined below, is never exposed to
the logical controller's scenario-data interface or to the service/runner, and
is zeroized with the handoff key.

The broker verifies only this directional HMAC document: exact principal pair,
attempt/lease/owner epoch, gate revision/hash/state, effect kind, sequence/prior
chain, same-boot `CLOCK_BOOTTIME` validity and one-use local consumption. It has
no Store credential or fallback query. Replay, expiry, wrong direction, stale
epoch/revision/chain, copied authority or mutation closes the attempted effect.
A snapshot is one no-FD canonical control datagram on the already authenticated
descriptor-198 `SOCK_SEQPACKET` channel; the existing peer-credential,
truncation/surplus and exact-payload rules apply. Broker acceptance returns one
frozen `OllamaEvidenceReleaseGateSnapshotAcceptanceV1` direction-reversed
message containing exactly `format`, `attempt_id`,
`operation_lease_hash`, `execution_owner_epoch`, `snapshot_hash`, `sequence`,
`effect_kind`, `snapshot_issued_boottime_ns`, `accepted_boottime_ns`,
`prior_acceptance_hash`, `sender_principal`,
`receiver_principal`, `key_id` and `authentication_hash`; principals are exactly
`ollama_evidence_broker_v1 -> studio_main_v1` and `format` is exactly
`worldforge_ollama_release_gate_snapshot_acceptance_v1`. Acceptance
authentication uses ASCII domain
`worldforge-ollama-release-gate-snapshot-acceptance-v1`, one NUL byte and those bounded
canonical fields with the authentication field omitted.
The first Acceptance prior hash is 64 zeroes and each later Acceptance names
the exact prior Acceptance hash. `snapshot_issued_boottime_ns` must equal the
snapshot field exactly, and
`snapshot_issued_boottime_ns <= accepted_boottime_ns` on the same boot.
Before entering the effect, broker atomically marks that sequence consumed in
its operation-owned immutable chain and emits the Acceptance. The broker itself
may then enter only `config_disclosure` or `fork_exec`; for
`listener_effect` it arms the exact causal observer and any vendor event before
Acceptance is drift, while for `request_send` the main-process logical
controller must verify the Acceptance before its one send attempt. The chain
admits each mapping at most once. An exact duplicate snapshot returns the same
Acceptance with no second entry. Broker loss discards execution eligibility and
triggers custody cleanup rather than reconstruction.
After HMAC/peer/chain validation, main records the exact Acceptance through
`release_snapshot_acceptance_record_v1`; only that committed target may source a
timing seal or later snapshot issuance. For request send this Store commit also
precedes the send-admission timing. A Store failure or unknown commit after a
broker-side effect makes the attempt non-evidence and cleanup-only; it never
permits an inferred Acceptance.
Acceptance loss looks up/retransmits those exact bytes and never repeats the effect; an
unknown consumption state is `deadline_race_indeterminate` and cleanup only.
A valid snapshot is only effect admission; because a tombstone or recovery fence
can race after issuance, the separate effect-timing document below decides
whether any resulting observation is usable evidence.

Descriptor 198 also carries one closed authenticated control chain; admission
snapshots alone never disclose a recipe. Main and broker derive a distinct
32-byte control key as HMAC-SHA256 of the raw handoff key over ASCII
`worldforge-ollama-control-key-v1`, one NUL byte each, attempt ID, lease hash and
decimal owner epoch. Its `key_id` hashes the raw key bytes. Every message below
uses HMAC-SHA256 over its exact `format` ASCII value, one NUL byte and the
bounded canonical document with only `authentication_hash` omitted. All message
types share one zero-based sequence and `prior_control_message_hash`: sequence
zero names 64 zeroes and every later message names the exact preceding complete
authenticated-message hash. No message from another attempt, epoch, recipe,
snapshot Acceptance or chain is accepted.

The embedded `OllamaCandidateConfigurationPayloadV1` has exactly `format`,
`candidate_recipe_hash`, `candidate_profile_hash`, `executable_realpath`,
`executable_hash`, `argv`, `environment`, `model_root_identity_hash`,
`numeric_loopback_origin`, `uid`, `gid`, `candidate_subgroup_hash`,
`descriptor_policy_hash`, `access_policy_hash`, `scratch_root_hash`,
`fork_safe_launcher_policy_hash` and `candidate_recipe_policy_hash`.
`format` is `worldforge_ollama_candidate_configuration_payload_v1`; argv and
the complete environment are bounded ordered built-in string arrays/maps from
the exact final operation recipe and must equal its duplicated fields byte for
byte. It contains no credential, HMAC key,
prompt, message, project data, provider response or log and is at most 65,536
canonical UTF-8 bytes.

`OllamaCandidateConfigurationOfferV1` has exactly `format`, `attempt_id`,
`authorization_hash`, `operation_lease_hash`, `execution_owner_epoch`,
`execution_owner_hash`, `release_snapshot_hash`,
`release_snapshot_acceptance_hash`, `candidate_recipe_hash`,
`candidate_profile_hash`, `limits_hash`, `configuration_payload`,
`configuration_payload_size`, `configuration_payload_hash`, `sequence`,
`prior_control_message_hash`, `sender_principal`, `receiver_principal`,
`key_id` and `authentication_hash`. Its format is exactly
`worldforge_ollama_candidate_configuration_offer_v1`; principals are
`studio_main_v1 -> ollama_evidence_broker_v1`; size is the exact canonical
payload byte count; and the payload hash is SHA-256 of those bytes. Main may
send this message exactly once, only after the exact `config_disclosure`
Snapshot Acceptance and before the timing document's first configuration byte.
The broker is inert before it: it has no executable/argv/environment/model-root
or candidate-launch recipe.

`OllamaCandidateConfigurationAcceptanceV1` has exactly `format`, `attempt_id`,
`authorization_hash`, `operation_lease_hash`, `execution_owner_epoch`,
`execution_owner_hash`, `offer_hash`, `release_snapshot_acceptance_hash`,
`candidate_recipe_hash`, `limits_hash`, `configuration_payload_size`,
`configuration_payload_hash`, `accepted_boottime_ns`, `sequence`,
`prior_control_message_hash`, `sender_principal`, `receiver_principal`,
`key_id` and `authentication_hash`. Its format is exactly
`worldforge_ollama_candidate_configuration_acceptance_v1`; principals reverse;
it names the exact Offer hash and bytes. Broker validates the peer, HMAC,
recipe/profile, payload schema/size/hash and current epoch before copying only
the frozen payload into its operation-owned recipe slot. Main must receive and
validate this Acceptance and seal the configuration effect timing before it may
request the later `fork_exec` snapshot. Every `limits_hash` in the Offer,
Acceptance, result and terminal is the byte-identical authorization/lease/
access-policy/final-recipe value; drift closes the channel.

`OllamaBrokerOperationResultV1` has exactly `format`, `attempt_id`,
`authorization_hash`, `operation_lease_hash`, `execution_owner_epoch`,
`execution_owner_hash`, `effect_kind`, `release_snapshot_hash`,
`release_snapshot_acceptance_hash`, `candidate_recipe_hash`,
`limits_hash`, `candidate_configuration_acceptance_hash`, `effect_observation_hash`,
`result_class`, `result_payload`, `result_payload_size`, `result_payload_hash`,
`sequence`, `prior_control_message_hash`, `sender_principal`,
`receiver_principal`, `key_id` and `authentication_hash`. Its format is exactly
`worldforge_ollama_broker_operation_result_v1`; principals are broker to main;
effect kind is only `fork_exec` or `listener_effect`; and the closed result
class is `spawn_observed`, `spawn_failed`, `listener_observed`,
`listener_drift` or `operation_failed`.
The embedded result payload has exactly `format`, `result_code`,
`primary_observation_hash`, nullable `secondary_observation_hash`,
`process_identity_count`, `descriptor_count`, `event_loss_count` and
`details_present`; its format is exactly
`worldforge_ollama_broker_result_payload_v1`, `result_code` repeats the closed
result class, `details_present` is false, and every bounded nonnegative count is
derived from the named observation. It is at most 16,384 canonical bytes and
cannot contain request, response, prompt, output, model text or raw log bytes.
The configuration Acceptance itself is the configuration-effect observation;
request-send observation remains main-local. For fork/listener, main sets the
later timing document's `effect_observation_hash` to this complete authenticated
result hash. The result therefore never names the not-yet-sealed timing hash and
cannot form a result/timing hash cycle.

`OllamaBrokerTerminalV1` has exactly `format`, `attempt_id`,
`authorization_hash`, `operation_lease_hash`, `execution_owner_epoch`,
`execution_owner_hash`, `candidate_recipe_hash`,
`limits_hash`,
`candidate_configuration_acceptance_hash`,
`last_release_snapshot_acceptance_hash`, `last_operation_result_hash`,
`candidate_subgroup_empty_hash`, `handoff_chain_hash`, `semantic_outcome_code`,
`terminal_class`, `sentinel_status`, `provider_semantic_body_present`,
`sequence`, `prior_control_message_hash`, `sender_principal`,
`receiver_principal`, `key_id` and `authentication_hash`. Its format is exactly
`worldforge_ollama_broker_terminal_v1`; principals are broker to main;
`provider_semantic_body_present` is the literal false; and outcome is only
`scenario_finished`, `scenario_failed` or `deadline_cleanup`.
`scenario_finished` requires `terminal_class=semantic_sentinel_125` and
`sentinel_status=125`; the other two require
`terminal_class=custody_failure_sentinel_126` and `sentinel_status=126`. It is
the final broker message before the matching sentinel exit. Crash, signal,
main-loss or action kill may prevent this message; those paths use only the
retained systemd terminal and never reconstruct a broker terminal. A failure
before configuration Acceptance likewise has no BrokerTerminal because its
required acceptance hash does not exist.

Each operation result and terminal requires an
`OllamaBrokerControlAckV1` with exactly `format`, `attempt_id`,
`operation_lease_hash`, `execution_owner_epoch`, `message_format`,
`message_hash`, `message_sequence`, `release_snapshot_acceptance_hash`,
`accepted_boottime_ns`, `sequence`, `prior_control_message_hash`,
`sender_principal`, `receiver_principal`, `key_id` and `authentication_hash`.
Its format is exactly `worldforge_ollama_broker_control_ack_v1`; principals are
main to broker. Broker performs no next transition and does not close/exit after
terminal until the exact ACK is verified. ACK loss retransmits the identical
message and lookup returns the identical ACK without a second effect. Wrong
peer, missing/substituted/replayed/oversized payload, sequence/chain drift,
surplus bytes, truncation, stale epoch/Acceptance or premature EOF closes the
channel and enters custody cleanup. After terminal ACK both ends close the
control channel and zeroize its key. The semantic provider request/response
body remains local to the main-process logical controller's exact bounded
anonymous wire mappings and is zeroized without file backing; it can never
masquerade as or be copied into the content-free
broker result/terminal protocol.

The exact canonical **payload** maxima, excluding the mandatory 88-byte outer
header, are 73,728 bytes for a configuration Offer, 8,192 for its Acceptance,
24,576 for an operation result, and 8,192 each for a terminal or control ACK.
The receiver compares the one `SOCK_SEQPACKET` record length to that payload
maximum plus exactly 88 before decoding and rejects an exact
duplicate unless its complete authenticated hash and sequence match the
already recorded message. Offer ACK loss returns the same configuration
Acceptance and never recopies configuration; result/terminal ACK loss follows
the rule above. Missing, substituted, replayed or oversized configuration or
result bytes cannot advance broker state.

The static `OllamaEvidenceNativeSingleThreadBrokerPolicyV1` has exactly
`format`, `broker_executable_hash`, `broker_build_id`,
`broker_library_closure_hash`, `broker_entrypoint_hash`,
`task_census_policy_hash`, `blocked_signal_policy_hash`,
`thread_api_surface_policy_hash`, `descriptor_198_policy_hash`,
`fork_safe_launcher_policy_hash`, `credential_policy_hash`,
`device_policy_hash`, `maximum_concurrent_launches` and
`policy_generation`. `format` is exactly
`worldforge_ollama_native_single_thread_broker_policy_v1` and
`maximum_concurrent_launches` is exactly one. It is static, contains no attempt,
lease, owner, configuration or final candidate-recipe hash, and is bound by the
custody policy before authorization.

The operation MainPID is a dedicated native, single-thread broker; it is never
Python or a general task executor. Before main may generate/deliver a key,
disclose configuration or issue launch admission, it freezes one
`OllamaEvidenceNativeSingleThreadBrokerV1` with exactly `format`, `attempt_id`,
`authorization_hash`, `operation_lease_hash`, `broker_recipe_hash`,
`native_single_thread_broker_policy_hash`,
`broker_executable_hash`, `broker_build_id`, `broker_library_closure_hash`,
`broker_pid`, `broker_start_time`, `broker_pidfd_identity_hash`,
`systemd_invocation_id`, `operation_cgroup_identity_hash`,
`self_task_dir_identity_hash`, `self_task_tid_census`,
`main_task_tid_census`, `thread_count`, `main_tid`, `signal_mask_hash`,
`broker_credential_snapshot`, `thread_api_surface_hash`, `fixed_launch_entrypoint_hash`,
`authority_state`, `observation_interval_hash` and `observed_at`. `format` is
exactly `worldforge_ollama_native_single_thread_broker_v1`;
`authority_state=pre_authority_single_thread_v1`, `thread_count=1`, and both
ordered censuses contain exactly the broker PID/TID. The broker obtains its
`/proc/self/task` census through a retained self dirfd while main independently
enumerates `/proc/<exact-pid>/task`; PID/start, task directory and both byte
censuses must agree. `broker_credential_snapshot` is the exact embedded
`CredentialSnapshotV1` defined in the custody section for this broker PID/start
and must satisfy the fixed operation-service account/capability contract.

The operation lease, custody policy and sacrificial custody proof bind the exact
`native_single_thread_broker_policy_hash`; the live observation above binds
that policy and the final broker identity. Main verifies the observation and
registers it by exact object identity before creating any handoff key or
configuration/launch authority. A decoded copy, subclass, `object.__new__`
lookalike, policy swap or post-observation mutation carries no authority.

The native broker links no threading runtime entry point, exposes no caller-set
clone flags and admits no `pthread_create`, `thrd_create`, `clone`, `fork`,
`vfork`, signal handler, audit hook, plugin, dynamic-load or callback surface.
Its sole process-creation authority is the construction-captured launcher below,
whose compiled `clone3` arguments cannot express `CLONE_THREAD` and whose
single in-flight state rejects a second/concurrent launch. Every catchable
signal is blocked before the pre-authority census and remains blocked until all
keys are zeroized and the broker has entered terminal cleanup. The broker
repeats the exact self/main task census before configuration Acceptance, before
launcher entry and before terminal handoff. A sibling TID, task-list mutation,
concurrent launch, signal-mask drift or callback surface makes thread creation
unavailable and therefore makes evidence execution unavailable, so no
key/configuration/launch authority is issued; if detected
after any authority or child effect, the attempt enters custody cleanup and
produces no evidence. This native broker and its proof do not exist today.

The pre-authorized static `OllamaCandidateRecipePolicyV1` has exactly `format`,
`candidate_execution_profile_hash`, `argv_derivation_policy_hash`,
`environment_derivation_policy_hash`, `origin_derivation_policy_hash`,
`model_root_derivation_policy_hash`, `scratch_derivation_policy_hash`,
`descriptor_derivation_policy_hash`, `required_operation_binding_set_hash` and
`policy_generation`. `format` is exactly
`worldforge_ollama_candidate_recipe_policy_v1`. It contains no attempt, lease,
owner epoch, subgroup, scratch root, selected origin or final recipe hash. Every
hash is a nonzero ordinary content reference to its named completed static
profile/policy document, generation is exactly one, and the serializer/4,096
byte bound and golden vector in the canonical-schema section are mandatory.

After the operation lease, subgroup and scratch root are frozen, main derives
one final `OllamaCandidateRecipeV1` with exactly `format`, `attempt_id`,
`authorization_hash`, `operation_lease_hash`, `execution_owner_epoch`,
`candidate_execution_profile_hash`, `candidate_recipe_policy_hash`,
`fork_safe_launcher_policy_hash`, `candidate_subgroup_hash`,
`scratch_root_hash`, `binary_closure_hash`, `executable_realpath`,
`executable_hash`, `argv`, `environment`, `model_root_identity_hash`,
`numeric_loopback_origin`, `account_name`, `group_name`, `uid`, `gid`,
`expected_groups`, `credential_policy_hash`, `device_profile`, `descriptor_policy_hash`,
`access_policy_hash`, `limits_hash` and `derived_at`. `format` is exactly
`worldforge_ollama_candidate_recipe_v1`; every operation value is derived by
the static policy, not supplied by a caller. This final document binds the
profile, launcher and exact limits one-way. The profile, recipe policy, launcher policy,
authorization and operation lease contain no final recipe hash.

The final recipe serializer uses `u53` for owner epoch/UID/GID, `utc35` for
`derived_at`, `path4096` for executable, a 1..64 ordered argv of strings whose
combined UTF-8 size obeys the launcher policy, and a 1..64 ordered environment
array of exact `{name,value,source}` objects with unique POSIX names. Source is
only `static_profile_v1`, `lease_derivation_v1`, `scratch_derivation_v1` or
`model_lock_v1`; one entry is exactly `OLLAMA_NO_CLOUD=1` from the static
profile, and every other entry/value must be enumerated by the recipe-policy
hash rather than inherited. `account_name`/`group_name` are `ollama`, expected
groups contain no distinct supplementary GID, device profile is
`cpu_only_no_device_v1`, numeric origin is exactly the authorized
`127.0.0.1:<port>`, executable hash is a raw-byte digest, attempt is an
independent ID, and every other `*_hash` is an already-complete content
reference. Canonical size is at most 65,536 bytes and there is no nullable or
unknown key.

Candidate creation uses only a frozen `OllamaEvidenceForkSafeLauncherV1`, with
exact fields `format`, `launcher_realpath`, `launcher_device`,
`launcher_inode`, `launcher_size`, `launcher_mode`, `launcher_sha256`,
`launcher_build_id`, `native_library_closure_hash`, `linux_architecture`,
`clone3_recipe_hash`, `signal_policy_hash`, `key_vault_policy_hash`,
`child_fd_policy_hash`, `fork_barrier_policy_hash`,
`credential_inheritance_policy_hash`, `credential_syscall_policy_hash`,
`candidate_execution_profile_hash`, `candidate_recipe_policy_hash`,
`preexec_allowed_syscalls`, `preexec_proc_fd_realpath`,
`preexec_proc_fd_open_flags`, `preexec_temporary_dirfd_role`,
`preexec_temporary_dirfd_cloexec`, `preexec_close_before_exec`,
`preexec_other_path_io_allowed`, `preexec_network_io_allowed`,
`preexec_device_io_allowed`, `candidate_access_policy_start_boundary`,
`maximum_argv_environment_bytes` and `policy_generation`. `format` is exactly
`worldforge_ollama_fork_safe_launcher_v1`. This construction-captured native
entry point is immutable and identity-registered before authorization. It uses
the direct Linux `clone3` ABI with exactly `CLONE_PIDFD|CLONE_INTO_CGROUP`,
`exit_signal=SIGCHLD` and the already retained candidate-subgroup cgroup FD;
there is no `subprocess`, `fork`, `posix_spawn`, `preexec_fn`, dynamic symbol
lookup or fallback. An unavailable syscall/flag or any native binary, library,
ABI, static profile/policy or method drift makes launch unavailable. This
pre-authorized launcher document never hashes an operation-derived
`OllamaCandidateRecipeV1`.

The added pre-exec fields are closed static launcher policy. The syscall array
is exactly `[close_range,openat,getdents64,fstat,fstatfs,close,dup3,
rt_sigaction,rt_sigprocmask,execve,exit_group,futex]`; the path is exactly
`/proc/self/fd`; open flags are exactly
`O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW`; the temporary role is
`launcher_proc_fd_census_dirfd_v1`; both closure booleans are true; all three
other-I/O booleans are false; and the access-policy boundary is exactly
`successful_candidate_exec_identity_observed_v1`. The launcher resolves the
procfs directory through the already pinned mount namespace, records its mount
ID, superblock device, inode, mode and statfs magic, uses the one temporary
read-only directory fd only for its exact `getdents64` census, and closes it
before the raw `execve`. No scratch/file writer, network socket, device node or
other path lookup exists in this pre-exec window. These rights belong solely to
the launcher policy; they are neither candidate rights nor an entry in
`OllamaEvidenceAccessPolicyV1`.

Every raw handoff, release-snapshot, control and deadline-action HMAC key held
by a process that can reach this launcher resides alone in an exact
host-page-sized anonymous `MAP_PRIVATE|MAP_ANONYMOUS` mapping. The code-owned
native key-vault authority applies and verifies both `MADV_DONTFORK` and
`MADV_DONTDUMP` before the key becomes usable, exposes only bounded pointer
operations to the fixed HMAC implementation, forbids Python `bytes`, allocator,
serialization, argv, environment, file, log, Store or shared-map copies, and
performs observed native zeroization before `munmap`. `MADV_DONTDUMP` limits
one dump path but is not a general secrecy claim. A missing flag, readable
child mapping, duplicate key material or unproved zeroization invalidates the
attempt.

Immediately before entering the native launcher, broker blocks every catchable
signal and seals the exact `fork_exec` Snapshot/Acceptance, configuration
Acceptance and recipe. From that point through child exec proof, the captured
native path invokes no Python callback, audit hook, allocator callback,
`pthread_atfork` callback or user code and performs no configurable lookup.
The child uses a fixed preallocated raw-syscall path. It first applies
`close_range(3, UINT_MAX, CLOSE_RANGE_UNSHARE)`, opens only `/proc/self/fd` for
an exact `getdents64` census, proves descriptors 0, 1, 2 and that temporary
census dirfd are the complete set, closes the census dirfd, and reaches the
code-owned non-secret shared-futex fork barrier with only descriptors 0, 1 and
2. Those roles are exactly read-only `/dev/null`, the authorized stdout sink
and the authorized stderr sink, with their recipe-bound identities and flags;
descriptor 198 and every control, key, configuration, census or scratch writer
is absent. The native parent independently verifies the retained child pidfd,
candidate cgroup, `/proc/<pid>/fd` census and absence of key-vault mappings,
then releases that one barrier. The child rechecks the release word, closes no
new descriptor, resets every catchable disposition and its mask to the exact
recipe through raw signal syscalls, and calls raw `execve` with only the
accepted immutable private argv/environment image; no shared writer can mutate
that image after `clone3`. The non-secret barrier mapping is neither a key nor
a configuration carrier and disappears at exec. `FD_CLOEXEC` remains
defense-in-depth; it never substitutes for the pre-exec census and closure.

The resulting frozen `OllamaEvidenceForkWindowObservationV1` has exactly
`format`, `attempt_id`, `authorization_hash`, `operation_lease_hash`,
`execution_owner_epoch`, `release_snapshot_acceptance_hash`,
`candidate_configuration_acceptance_hash`, `candidate_recipe_hash`,
`launcher_policy_hash`, `launcher_identity_hash`, `native_library_closure_hash`,
`linux_boot_id`, `broker_process_identity_hash`, `broker_task_census_hash`,
`fork_outcome`, nullable `candidate_process_identity_hash`, nullable
`candidate_pidfd_identity_hash`, nullable `candidate_cgroup_identity_hash`,
`signal_mask_before_hash`, `signal_mask_after_hash`, `python_callback_count`,
`audit_callback_count`, `atfork_callback_count`, `key_vault_mapping_census_hash`,
`broker_credential_snapshot`, `child_preexec_credential_snapshot`, nullable
`candidate_postexec_credential_snapshot`, `credential_syscall_census`,
`child_fd_census_hash`, `parent_fd_census_hash`, `configuration_writer_census_hash`,
nullable `preexec_procfs_mount_identity_hash`, nullable
`preexec_proc_fd_directory_identity_hash`, nullable
`preexec_temporary_dirfd_number`, nullable `preexec_temporary_dirfd_closed`,
nullable `candidate_access_policy_start_observation_hash`,
`fork_barrier_observation_hash`, `exec_identity_observation_hash`,
`observation_loss_count` and `observed_at`. `format` is
exactly `worldforge_ollama_fork_window_observation_v1`; all three callback
counts and the loss count are zero, and every census is complete.
`fork_outcome` is only `exec_observed_v1`, `pre_clone_failed_v1`,
`child_setup_failed_v1` or `exec_failed_v1`. Only `exec_observed_v1` permits all
three candidate identity fields and `candidate_postexec_credential_snapshot`
non-null; for it, the temporary fd number is a `u53`, both pre-exec identity
hashes are exact completed observations, `preexec_temporary_dirfd_closed=true`,
and the boundary observation proves that the first candidate-policy effect is
strictly after successful exec identity. `pre_clone_failed_v1` requires the
three procfs/fd fields and boundary hash null; later failures bind the exact
nullable presence and closure history, always leave the boundary hash null,
and never invent a candidate-policy effect. Number and closure are both null
iff the temporary fd was never created; once created both are non-null and
usable cleanup requires closure true. Every failure
keeps the candidate identity fields canonical null and binds
its exact no-child or terminal-child census in the remaining observation
fields. `preexec_procfs_mount_identity_hash` names an exact
`LauncherProcfsMountIdentityV1` document with ordered keys `format`,
`linux_boot_id`, `mount_namespace_inode`, `mount_id`, `parent_mount_id`,
`major_minor`, `root`, `mount_point`, `filesystem_type`, `mount_options`,
`super_options`, `statfs_magic` and `observed_boottime_ns`; its format is
`worldforge_ollama_launcher_procfs_mount_identity_v1`, numeric fields are
`u53`, the root/mount point are normalized absolute paths, filesystem type is
exactly `proc`, and the two option arrays are sorted duplicate-free ASCII.
`preexec_proc_fd_directory_identity_hash` names an exact
`LauncherProcFdDirectoryIdentityV1` document with ordered keys `format`,
`candidate_pid`, `candidate_start_time`, `realpath`, `device`, `inode`, `mode`,
`uid`, `gid`, `fd_number`, `open_flags`, `mount_identity_hash`,
`opened_boottime_ns` and `closed_boottime_ns`; its format is
`worldforge_ollama_launcher_proc_fd_directory_identity_v1`, the requested
static path is `/proc/self/fd` while `realpath` is exactly the normalized
`/proc/<candidate_pid>/fd` resolution, scalar identities are `u53`, role/flags
equal the launcher policy, and open precedes close. Both are bounded canonical documents under the
global hash rule. On success,
`candidate_access_policy_start_observation_hash` is exactly equal to the
already complete `exec_identity_observation_hash`; there is no second boundary
document or hidden pre-exec candidate authority. The broker and child values are exact embedded `CredentialSnapshotV1`
objects, the post-exec value matches the candidate PID/start, and
`credential_syscall_census` is an ordered zero-count map for the closed
forbidden syscall set. Broker restores its captured signal mask only
after exact candidate executable, PID/start, cgroup and pidfd proof or completed
failure cleanup. Fork/exec/preexec drift, a child key or
descriptor-198 acquisition, any surplus FD/writable mapping, a callback or
signal-window mutation, uncertain exec, or incomplete observation yields no
evidence and invokes custody cleanup. This launcher and its live proof do not
exist today.

The separate frozen `OllamaEvidenceListenerObservationV1` has exactly `format`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`,
`execution_owner_epoch`, `release_snapshot_acceptance_hash`,
`candidate_recipe_hash`, `listener_policy_hash`, `service_process_identity_hash`,
`expected_numeric_loopback_tuple`, `listener_outcome`, nullable
`observed_listener_identity_hash`, nullable `causal_peer_state_hash`,
`socket_census_hash`, `observation_interval_hash`, `observation_loss_count` and
`observed_at`. `format` is exactly
`worldforge_ollama_listener_observation_v1`; `listener_outcome` is only
`exact_listener_observed_v1`, `listener_drift_v1` or `observer_failed_v1`.
Only the exact-observed branch permits both nullable identities non-null; every
other branch keeps them null, records the closed failure in the census and
cannot support a request.

`OllamaBrokerOperationResultV1` binds the primary observation one-way. The
allowed mapping is exact: `fork_exec/spawn_observed` requires a
ForkWindowObservation with `exec_observed_v1`; `fork_exec/spawn_failed`
requires that type with `child_setup_failed_v1` or `exec_failed_v1`;
`fork_exec/operation_failed` requires that type with `pre_clone_failed_v1`;
`listener_effect/listener_observed` requires a ListenerObservation with
`exact_listener_observed_v1`; `listener_effect/listener_drift` requires that
type with `listener_drift_v1`; and `listener_effect/operation_failed` requires
that type with `observer_failed_v1`.
`result_payload.primary_observation_hash` and the result's
`effect_observation_hash` are that exact observation hash; the v1 secondary
observation is always canonical null. No other class/type/outcome pair exists.
The observation hashes no result or timing, the result hashes the observation,
and `OllamaEvidenceOperationEffectTimingV1` hashes the complete authenticated
result: `Observation -> BrokerOperationResult -> OperationEffectTiming` is the
sole fork/listener DAG.

The immutable `OllamaEvidenceDeadlineFiredV1` has exactly `format`,
`release_gate_id`, `attempt_id`, `authorization_hash`, `operation_lease_hash`,
`deadline_tombstone_key_hash`,
`execution_owner_epoch`, `execution_owner_hash`, `linux_boot_id`,
`deadline_boottime_ns`, `timer_on_boot_usec`, `deadline_timer_invocation_id`,
`deadline_action_invocation_id`, `fired_boottime_ns`,
`pre_fire_release_state_hash`, `event_id`, `event_payload_hash` and
`committed_at`. `format` is exactly
`worldforge_ollama_evidence_deadline_fired_v1`. Its deterministic Store key is
the independently gate-bound `deadline_tombstone_key_hash`; exactly one insert
is allowed.
In one Store transaction the deadline action inserts these exact bytes and CASes
the release state to its matching fired state before asking PID1 to stop/kill
the operation unit. An exact ACK-loss retry returns the same tombstone. Changed
bytes, another timer/action invocation or a second key are rejected. If durable
insertion is unavailable, a defense-in-depth kill may still run, but evidence
cleanup is unproven and the launch lock remains closed.

The frozen `OllamaEvidenceDeadlineActionLifecycleV1` has exactly `format`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`, `release_gate_id`,
`deadline_tombstone_key_hash`,
`execution_owner_epoch`, `execution_owner_hash`, `state`, positive `generation`,
nullable `prior_lifecycle_hash`,
`systemd_deadline_timer_name`, `systemd_deadline_timer_object_path`,
`systemd_deadline_action_name`, `systemd_deadline_action_object_path`, nullable
`deadline_action_static_install_hash`, nullable
`deadline_credential_source_hash`, nullable `deadline_action_load_recipe_hash`, nullable
`deadline_action_load_observation_hash`, nullable
`timer_start_transaction_hash`, nullable `deadline_timer_invocation_id`,
nullable `deadline_action_invocation_id`, nullable `deadline_action_result`,
nullable `deadline_timer_properties_hash`, nullable
`deadline_action_properties_hash`, nullable `deadline_tombstone_hash`,
nullable `fire_committed_boottime_ns`, nullable
`terminal_finalize_deadline_boottime_ns`, nullable `terminal_finalizer`,
`manager_observation_hash`, `event_id`, `event_payload_hash` and `committed_at`.
`format` is exactly
`worldforge_ollama_evidence_deadline_action_lifecycle_v1`; `state` is exactly
`not_created`, `static_action_loaded_inactive`, `armed_not_invoked`,
`fire_committed_pending_terminal` or `invoked_terminal`.

`not_created` requires every nullable install/credential/load, transaction, invocation,
result, property, tombstone, fire, finalization-deadline and finalizer field to
be canonical JSON `null` and an authenticated manager absence observation after
the lease exists. `static_action_loaded_inactive` requires the exact static
install hash, ready credential-source hash, post-capability load-recipe hash,
load observation and action-property hash non-null while the timer
transaction/invocation/property, action invocation/result, tombstone, fire and
finalization fields remain null. `armed_not_invoked` preserves those five
static-action fields and additionally requires a non-null timer transaction,
timer invocation and timer-property hash; action invocation/result, tombstone,
fire, finalization-deadline and finalizer remain null. In both states PID1 proves
the static action instance is loaded, inactive and has never run.
`fire_committed_pending_terminal` requires the transaction, timer/action
invocations, static install/credential/load-recipe/load-observation, both property hashes, tombstone, fire time and finalization
deadline non-null, while action result and finalizer remain null.
`invoked_terminal` requires every transaction, timer/action invocation, result,
install/credential/load-recipe/load-observation, property, tombstone, fire,
deadline and finalizer field non-null;
`terminal_finalizer` is only `deadline_action_port_v1` or
`recovery_timeout_v1`. No other null combination is valid. Normal completion
seals the loaded `armed_not_invoked` hash before closing an action that never
ran; a failure before static instance load seals `not_created`, while a failure
after static load and before timer arm seals `static_action_loaded_inactive`; a fired action must pass
through `fire_committed_pending_terminal` before `invoked_terminal`.
For `deadline_action_load_transition_v1`, the ready credential-source hash is
an ordered committed source of the lifecycle target. The load-recipe hash is an
opaque request-integrity scalar that must byte-equal the immediately preceding
`static_action_load_v1` manager result's `request_hash`; it is not a hidden
same-event target or backward edge.

Both `deadline_action_terminal_v1` finalizers are same-boot operations. Before
either compares `terminal_finalize_deadline_boottime_ns`, the transaction
revalidates that the current Linux boot ID equals the OperationLease boot ID
and the boot bound by the lifecycle's timer/action observations. Only then may
the action port test “strictly before” or the recovery finalizer test “at or
after” in that one `CLOCK_BOOTTIME` domain. If the boot IDs differ, the old
pending lifecycle remains byte-for-byte immutable: no deadline comparison,
wait, timeout finalizer, `invoked_terminal` projection or PID1-result
reconstruction is legal. Its only later representation is the separately
committed reboot-abandonment projection after current-boot cleanup.

The prerequisite `OllamaDeadlineActionStaticInstallV1` has exactly `format`,
`systemd_manager_identity_hash`, `systemd_version_hash`,
`template_unit_name`, `template_unit_realpath`, `template_unit_device`,
`template_unit_inode`, `template_unit_mode`, `template_unit_uid`,
`template_unit_gid`, `template_unit_size`, `template_unit_sha256`,
`helper_realpath`, `helper_device`, `helper_inode`, `helper_mode`, `helper_uid`,
`helper_gid`, `helper_size`, `helper_sha256`, nullable `helper_build_id`,
`helper_library_closure_hash`, `exec_start_argv_hash`,
`credential_directive_hash`, `unit_properties_hash`, `install_generation` and
`observed_at`. `format` is exactly
`worldforge_ollama_deadline_action_static_install_v1`; the template name is
exactly `worldforge-ollama-evidence-deadline@.service`, every integer is a
nonnegative JavaScript-safe integer, hashes are lowercase 64-hex, and all paths
are absolute normalized realpaths no longer than 4,096 UTF-8 bytes. The
template pins the code-owned helper, fixed argv shape, `Type=oneshot`,
`RemainAfterExit=yes`, `Restart=no`, `CollectMode=inactive`, the narrow Store
port and the exact encrypted-credential directive. Its instance is exactly
`worldforge-ollama-evidence-deadline@<lease_id>.service`. Installation or
mutation is outside this ADR: an already installed template/helper must be
hash-attested before authorization and revalidated before instance load. No
matching installed document or live unit semantics have been proven on this
host, so evidence execution remains unavailable.

The deadline action is the sole Store-writer exception and is never the
candidate, controller or broker. A construction-owned,
identity-registered `OllamaDeadlineActionStoreAuthority` issues one frozen
`OllamaDeadlineActionStoreCapabilityV1` with exactly `format`, `capability_id`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`,
`execution_owner_epoch`, `execution_owner_hash`, `release_gate_id`,
`deadline_tombstone_key_hash`,
`base_release_revision`, `deadline_boottime_ns`, `timer_unit_name`,
`action_unit_name`, `action_invocation_id`, `action_recipe_hash`, `action_executable_hash`,
`action_argv_hash`, `action_cgroup_hash`, `action_invocation_policy_hash`,
`store_method_set_hash`, `limits_hash`, `terminal_finalize_timeout_ns`,
`not_before_boottime_ns`, `expires_boottime_ns`, `nonce`,
`capability_nonce_hash`, `key_id` and `authentication_hash`. `format` is exactly
`worldforge_ollama_deadline_action_store_capability_v1`; `nonce` and the HMAC key
are distinct 32-byte kernel-CSPRNG values, `capability_nonce_hash` is the exact
raw nonce hash, and both IDs are computed byte-for-byte by the global formulas
before this document. They cannot be supplied by a caller or derived from this
capability's content/HMAC/event hash. `action_invocation_id` is pinned in the fixed
action argv and credential and is distinct from the PID1-generated InvocationID.
`action_invocation_policy_hash` freezes the exact PID1 manager, timer
transaction, unit/cgroup, executable/argv, encrypted-credential role, local
Store-port endpoint, peer-verification algorithm and InvocationID binding.
`key_id` is SHA-256 over the raw HMAC key. The method-set hash names only
`compare_and_fire_deadline_v1` and `append_deadline_action_terminal_v1` in that
order. Authentication uses the raw key and ASCII domain
`worldforge-ollama-deadline-action-store-capability-v1` under the global HMAC
rule above. `not_before_boottime_ns` equals lease opening and
`expires_boottime_ns` equals the logical deadline; checked same-boot ordering is
mandatory. `terminal_finalize_timeout_ns` equals the operation lease's frozen
positive value and cannot be supplied by the action or caller.
`limits_hash` equals the authorization, scenario, access-policy, lease and
candidate-recipe value.

The installed template's fixed directive is exactly
`LoadCredentialEncrypted=worldforge.deadline-action-store-capability-v1:/run/worldforge-ollama-evidence-credentials/%i.cred`.
The static install, authorization and capability bind only that directive, the
credential-name/path-derivation/parent-identity/decryption/size policy and the
capability identity. They contain no actual source dev/inode/stat, ciphertext
size/hash, ready-source hash or future load-recipe hash. After capability
registration, main must commit credential-source pending, materialize the one
bounded systemd-encrypted ciphertext under the exact creation protocol, seal
the exact credential-file observation, commit ready from that cause, and
derive the one-way load recipe before calling PID1. A different
directive, source generation, path, ciphertext identity or transient-unit
credential property is invalid. The source is a trusted control-plane sink
outside the candidate access policy and contains ciphertext only; raw key bytes
never cross D-Bus, argv, environment or a writable candidate sink.

At helper entry, code
opens the exact PID1 credentials directory to a retained dirfd, verifies its
unit/mount/ownership identity, then uses only that dirfd plus `openat2` with no
symlink/magic-link traversal,
relocates the read-only credential to reserved descriptor 197 with `FD_CLOEXEC`,
validates the full bytes/HMAC, and closes the arrival. Neither argv, environment,
scratch, log nor Store contains the raw key. Rejected/expired credentials and
normal completion zeroize helper, issuer and narrow-port key copies. Every path
then commits the exact deadline-credential cleanup proof before outer cleanup;
missing source closure, zeroization, exact-inode unlink, parent fsync or ENOENT
proof is cleanup-unproven.

The helper has no StudioStore path, SQL, table, cursor, generic key/value or read
authority. It may send exactly one bounded request on the fixed local
`StudioStoreDeadlineActionPort`; that construction-owned port exposes only the
two methods named above. The port is a durable authenticated StudioStore
authority outside the evidence main and operation units; the custody proof pins
its executable/process/local-endpoint identity and proves it remains reachable
after sacrificial main loss. Port loss never grants a fallback database path: a
defense kill may proceed, but the attempt remains cleanup-unproven. Before
accepting the first method it verifies the
credential HMAC and one-use nonce, `SO_PEERCRED`, exact helper PID/start,
executable hash, fixed argv and action-invocation ID, action unit/cgroup, fresh
PID1 action InvocationID,
timer transaction/invocation, attempt/lease/owner epoch, gate revision, deadline
and capability window. The current gate must descend from
`base_release_revision` through only the exact armed/released transitions above;
any alternate revision chain is rejected. `compare_and_fire_deadline_v1` is one
narrow transaction: it consumes the nonce, verifies current
owner/gate/capability fields, changes
only `inert_unarmed|inert_armed` to `fired_before_release` or `released` to
`fired_after_release`, inserts the exact tombstone, and CASes the lifecycle from
`armed_not_invoked` to `fire_committed_pending_terminal`. That same transaction
sets `fire_committed_boottime_ns` to the tombstone fire time and sets
`terminal_finalize_deadline_boottime_ns` to checked
`fire_committed_boottime_ns + terminal_finalize_timeout_ns`; the result must be
no later than the frozen outer cleanup bound
`deadline_boottime_ns + max_enforcement_latency_usec*1000`. Gate, tombstone and
pending lifecycle either all commit or none does. ACK loss looks up the consumed
nonce/tombstone and returns the same pending lifecycle.

The port retains that verified invocation and may then perform only
`append_deadline_action_terminal_v1`, which binds the same tombstone, action
InvocationID, retained PID1 result and lifecycle transition to
`invoked_terminal`; no other record can be read or written. Its result document
has the closed class `completed`, `crash_exit`, `crash_signal`, `timeout`,
`manager_failure` or `result_unavailable` plus the exact retained PID1
properties and observer hash. `result_unavailable` can close the lifecycle but
cannot support provider/scenario evidence and is not itself a cleanup proof;
cleanup may complete only from the separately authenticated systemd/domain,
socket, sink and device fixed-point observations. If any required conjunct is
unavailable, recovery becomes `failed` and the launch lock remains closed. The
first method must enter within the original
capability window. After atomic fire consumption, only that exact invocation's
terminal append remains valid strictly before the finalization deadline and
sets `terminal_finalizer=deadline_action_port_v1`.

Recovery acquisition invalidates every unused old-epoch action capability. If
and only if the exact lifecycle is already
`fire_committed_pending_terminal` **and the current boot equals the lease
boot**, it instead marks this one method
`finalization_only`; that append is the sole old-epoch Store transition still
permitted. Recovery waits for a valid action-port finalization until the exact
deadline. At or after it, the old capability is rejected, the current recovery
owner observes/stops the retained action and may append the exact terminal with
`terminal_finalizer=recovery_timeout_v1`. No other old-epoch write, effect or
manager action is accepted. With an unequal boot, recovery never marks the
method finalization-only and follows only the reboot-abandonment contract
above. Replay, wrong identity/field/epoch/revision/
invocation, expiry before fire, copied authority or HMAC failure performs no
Store transition. A partial or unprovable finalization leaves cleanup unproven
and the Studio lock closed.
The fire and recovery-acquisition CASes serialize on the same expected owner,
gate and lifecycle generations: fire-first yields pending-finalization under
the exception; recovery-first rejects fire. There is no third partial state.

The frozen `OllamaEvidenceOperationEffectTimingV1` has exactly `format`,
`effect_kind`, `effect_authority`, `effect_sequence`, `attempt_id`, `authorization_hash`,
`operation_lease_hash`, `execution_owner_epoch`, `execution_owner_hash`,
`release_snapshot_hash`, `release_snapshot_acceptance_hash`,
`predecessor_effect_timing_hash`, `snapshot_issued_boottime_ns`,
`snapshot_accepted_boottime_ns`, `linux_boot_id`, `deadline_boottime_ns`, nullable
`deadline_tombstone_hash`, nullable `tombstone_fired_boottime_ns`, nullable
`recovery_fence_hash`, nullable `recovery_fence_boottime_ns`,
`admission_boottime_ns`, `effect_enter_boottime_ns`,
`effect_return_boottime_ns`, `effect_observation_hash`, nullable
`first_request_byte_observed_boottime_ns`, nullable
`last_request_byte_observed_boottime_ns`, `effect_units`,
`request_bytes_observed`, `ordering_class`, `observation_hash`, `event_id` and
`event_payload_hash`. `format` is
exactly `worldforge_ollama_operation_effect_timing_v1`; `effect_kind` is the same
closed literal carried by its release snapshot; `effect_sequence` is exactly
that snapshot's zero-based `sequence + 1`; the Acceptance hash must name the
exact authenticated acceptance for that snapshot; and every timestamp is read
from the same boot's `CLOCK_BOOTTIME`. `ordering_class` is only `no_effect`,
`strictly_before_all_fences` or `deadline_race_indeterminate`.
`effect_authority` is exactly `ollama_evidence_broker_v1` for configuration and
fork/exec, `ollama_evidence_listener_observer_v1` for the vendor listener event,
and `studio_main_ollama_controller_v1` for request send; no other mapping is
accepted.
`snapshot_issued_boottime_ns` must equal the snapshot's issued value and
`snapshot_accepted_boottime_ns` must equal the Acceptance's accepted value;
neither may be resampled or caller supplied.

`no_effect` requires `effect_units` and byte count zero, both request-byte fields
canonical null, and an observation proving the attempted boundary caused no
configuration disclosure, fork/exec, listener effect or send. A completed
non-send effect requires `effect_units=1`, zero request bytes and null byte
timestamps. A request send uses exactly one code-owned non-retried syscall;
effect units, its exact returned byte count, and same-clock first/last captured
request-byte times are nonzero/non-null and must equal the fixed request length.
For configuration, `effect_observation_hash` is the exact complete authenticated
configuration-Acceptance hash; for fork/listener it is the exact complete
authenticated BrokerOperationResult hash whose payload binds the causal census;
for request send it is the main-local code-owned send-observation hash.
`observation_hash` binds the clock identity/read sequence and capture completeness
for this timing document.
The timing becomes sealed only as the
`operation_effect_timing_seal_v1` target above; its target-body preimage omits
the two declared event fields, and its final content hash includes their exact
resolved values. An in-memory timing or observation hash is not a predecessor
authority.
Every effect needs a fresh matching current-epoch snapshot and Acceptance. The
exact same-clock inequalities are
`snapshot_issued_boottime_ns <= snapshot_accepted_boottime_ns <=
admission_boottime_ns <= effect_enter_boottime_ns <=
effect_return_boottime_ns`. The first effect names 64 zeroes as predecessor;
each later effect names the exact sealed prior timing and additionally requires
`prior.effect_return_boottime_ns <= snapshot_issued_boottime_ns`. Issuance,
acceptance, admission, enter, return and the entire causal observation must fall
inside the snapshot validity window and strictly before the logical cutoff, any
tombstone/recovery fence, and the conservative lower bound of every later
owner-loss/revocation cutoff; final validation also requires the snapshot
expiry itself strictly before that lower bound. Main verifies and durably seals
the authenticated
timing before it can issue the next snapshot. A partial/unknown effect, stale
epoch/snapshot/Acceptance, predecessor drift, any value at or after a boundary,
an interval spanning a boundary, or unprovable ordering is
`deadline_race_indeterminate`, yields no usable evidence and is never retried.

After `opening`, the only eligible manager is the live-proven **system** systemd
PID1 reached through the construction-owned authenticated D-Bus authority.
Before its first manager call, one Store transaction registers the independently
derived tombstone/recovery key, the exact `release_gate_id` and the initial
`inert_unarmed` gate plus `not_created` action lifecycle and the exact
deadline-action capability ID, nonce hash, key ID and method-set hash. It stores
no raw capability key. ACK loss looks up those same bytes; another key/ID or
prior manager-effect journal is rejected. Only
then may manager effects begin.

The operation-unit create, static-action load and timer create are separately
idempotent by lease ID, exact names/object paths, opening hash and property
snapshots. A matching existing object/transaction returns the same invocation
and persisted deadline; any property, invocation, transaction or boot mismatch
fails closed. Before the first manager effect, main requires the exact custody
proof below and confirms its systemd/kernel/plan/profile hashes still match.
Every manager request, D-Bus serial/job lookup, reply and property snapshot
binds the current `execution_owner_epoch` and owner hash. Its exact transaction
journal records call-entry/reply `CLOCK_BOOTTIME`; if an owner recovery fence
wins before or overlaps an allocated manager effect, or if either timestamp is
not strictly below the later owner-cutoff lower bound, recovery treats the
object as old-epoch resources and kills it through the registered lease instead
of continuing the scenario. A manager journal from an old execution or recovery
epoch never authorizes another effect.
Before each create or lookup it computes
`remaining_ns = deadline_boottime_ns - current CLOCK_BOOTTIME`; a
nonpositive value forbids every new operation/timer/action manager effect and
candidate release.

Creation uses inert custody to remove the action-fired/operation-create race.
Main first creates one `AF_UNIX/SOCK_SEQPACKET|SOCK_CLOEXEC` socketpair, enables
and verifies `SO_PASSCRED=1` on both endpoints, retains the main endpoint and
passes only the broker endpoint in the authenticated operation-service
`StartTransientUnit` call. Before that call, main proves its reserved slot 198
vacant, relocates its own
endpoint with `dup3(..., 198, O_CLOEXEC)`, closes the arrival descriptor and
attests the exact `/proc/self/fd/198` role; the attached broker endpoint is the
only remaining non-main duplicate. The exact D-Bus method signature is
`ssa(sv)a(sa(sv))`: deterministic operation-unit name, mode `fail`, the frozen
`a(sv)` property array, and an exact empty auxiliary-unit array. The required
stdio-FD properties are `(StandardInput, variant s, "fd")` and
`(StandardInputFileDescriptor, variant h, the UNIX_FD index for that exact
socket endpoint)`. The broker-ready credential property is
`(SetCredentialEncrypted, variant a(say), [("worldforge.broker-ready-key-v1",
exact encrypted byte array)])`; it carries ciphertext only. No socket unit,
`LISTEN_FDS`, `sd_listen_fds`, `Accept=`, fd-name routing or other socket
activation mechanism is claimed or permitted. The property order, D-Bus type
signatures, attached-FD census, method bytes, reply/job and PID1 property
snapshot are all frozen. Local static documentation has not proved that this
host accepts and preserves the `StandardInputFileDescriptor` transient property
with these semantics: systemd 255's transient-settings list omits it and the
interface exposes only non-equivalent
`StandardInputFileDescriptorName:s` observation. That exact live conformance is
a prerequisite. There is
no fallback property or inherited-stdin guess, so execution is unavailable
until it passes.

The same frozen operation-service property array has one credential and device
strategy only: `(Type,s,"exec")`, `(User,s,"ollama")`,
`(Group,s,"ollama")`, `(SupplementaryGroups,as,[])`,
`(DynamicUser,b,false)`, `(NoNewPrivileges,b,true)`,
`(AmbientCapabilities,t,0)`, `(CapabilityBoundingSet,t,0)`,
`(DevicePolicy,s,"closed")` and `(DeviceAllow,a(ss),[])`. There is no
supplementary-group, ambient-capability, device or dynamic-user override. The
installation observation binds the locally resolved numeric UID/GID and exact
account-database identity; the final profile and recipe repeat those observed
numbers. Values such as the currently observed 996/983 are evidence for this
host, not portable constants or caller inputs. Any unit-property substitution
or a different account resolution is manager drift and enters retained-domain
cleanup.

PID1 starts the exact inert operation service with `Type=exec` and the broker as
MainPID. At native entry the broker blocks every catchable signal, performs its
one-TID and descriptor census, verifies fd 0 is the exact passed
`AF_UNIX/SOCK_SEQPACKET` endpoint (`SO_TYPE`, socket cookie/peer identity and
`SO_PASSCRED=1`), proves fd 198 vacant, executes
`dup3(0, 198, O_CLOEXEC)`, closes fd 0 and every surplus descriptor, then
reattests `/proc/self/fd/198`, peer credentials and its closed descriptor-role
census. It reads the separately encrypted one-use 32-byte broker-ready key only
from the exact systemd credential role into a DONTFORK/DONTDUMP page. Any wrong,
missing or extra stdin/credential/FD, non-SEQPACKET socket, peer drift, failed
dup/census or thread/signal drift exits custody sentinel 126 without candidate
release.

Every native broker, clone child immediately before `execve`, post-exec service
and discovered runner freezes the same exact `/proc/<pid>/status` credential
snapshot. The embedded `CredentialSnapshotV1` has exactly `pid`, `start_time`,
`uid_real`, `uid_effective`, `uid_saved`, `uid_filesystem`, `gid_real`,
`gid_effective`, `gid_saved`, `gid_filesystem`, `groups`, `cap_inheritable`,
`cap_permitted`, `cap_effective`, `cap_bounding`, `cap_ambient`,
`no_new_privs`, `status_bytes_hash` and `observed_boottime_ns`. PID/start and
all numeric values are nonnegative JavaScript-safe integers; `groups` is the
exact ordered numeric `Groups:` census, contains no duplicate, and after
removing an optional entry equal to the primary GID is empty. All four UIDs
equal the profile's observed UID, all four GIDs equal its observed GID, all five
capability masks are exactly sixteen lowercase hexadecimal zeroes and
`no_new_privs=1`. The child inherits this snapshot and the fixed launcher
forbids `setuid`, `setgid`, `setreuid`, `setregid`, `setresuid`, `setresgid`,
`setfsuid`, `setfsgid`, `setgroups`, `capset` and credential-changing `prctl`
between clone and exec; the fork-window observer records an exact zero-call
census for that closed set. Post-exec service and runner snapshots must match
the recipe. A missing status field, credential syscall, group/capability drift
or UID/GID change yields no evidence and kills the retained candidate domain.

The first descriptor-198 record is the HMACed
`OllamaEvidenceBrokerReadyV1`, with exactly `format`, `attempt_id`,
`authorization_hash`, `operation_lease_hash`, `execution_owner_epoch`,
`systemd_manager_identity_hash`, `systemd_unit_name`, `systemd_invocation_id`,
`broker_pid`, `broker_start_time`, `broker_executable_hash`,
`broker_native_policy_hash`, `single_tid_observation_hash`,
`stdin_arrival_identity_hash`, `descriptor_198_identity_hash`,
`descriptor_census_hash`, `peer_credential_hash`, `ready_boottime_ns`,
`sender_principal`, `receiver_principal`, `ready_key_id` and
`authentication_hash`. Format is exactly `worldforge_ollama_broker_ready_v1`,
principals are exactly `ollama_evidence_broker_v1 -> studio_main_v1`, key ID is
SHA-256 over the raw ready key, and authentication is HMAC-SHA256 over ASCII
`worldforge-ollama-broker-ready-v1`, one NUL byte and the bounded canonical
document with only `authentication_hash` omitted. It is record code 12,
channel sequence 0 and at most 4,096 payload bytes. The ready key authenticates
only this single record; it is not the custody
handoff, control, snapshot or deadline-action key and grants no descriptor,
configuration or launch capability. Main must receive, validate
and durably bind that exact record plus independent PID1 and `/proc` broker proof
within `broker_ready_timeout_ns`; broker and main then zeroize all ready-key
copies. Missing/late/substituted/replayed Ready, ACK uncertainty or proof drift
kills and cleans the retained inert unit. `sd_notify`/`READY=1`, `Type=notify`
and `NotifyAccess` are absent and cannot substitute.

Only after valid BrokerReady does the broker maintain its main-loss lease,
receive authenticated custody handles and close the empty candidate subgroup.
In this state it has no candidate recipe/configuration, listener, provider
socket or scratch disclosure sink.

Main next revalidates the already installed
`OllamaDeadlineActionStaticInstallV1`, commits the exact pending credential
source, materializes/fsyncs the encrypted attempt-specific capability file,
seals the exact credential-file observation, commits the exact ready source
from that cause, and derives the post-capability load recipe.
Only then may it invoke PID1 `LoadUnit` with exact D-Bus signature `s -> o` for
`worldforge-ollama-evidence-deadline@<lease_id>.service`. It proves the returned
object is the same fixed template instance, and the manager result's request
hash must equal that load recipe. On the same authenticated D-Bus
connection, before any property/hash attestation or lifecycle CAS, main
immediately calls `RefUnit` with exact signature `s -> ()` for that exact unit
name and journals its reply as `static_action_ref_v1`. A missing/ambiguous reply
is not a retained reference. Main then proves the referenced instance is loaded
but inactive, has never run, and matches every installed
template/helper/credential/property hash, and CASes the lifecycle
`not_created -> static_action_loaded_inactive` only through
`deadline_action_load_transition_v1`. That CAS consumes, in order, the already
committed `static_action_load_v1` and `static_action_ref_v1`
`OllamaManagerEffectResultV1` hashes plus their exact shared connection identity;
the composite load observation binds those same results, the exact ready
credential-source hash and the post-capability load-recipe hash. It does not start the
action.

Main then makes exactly one timer-primary `StartTransientUnit` call using the
same `ssa(sv)a(sa(sv))` signature, mode `fail`, the frozen timer `a(sv)`
properties and an exact empty auxiliary-unit array. PID1 must arm the timer whose
same-basename implicit target is that already loaded static action instance;
the transient array contains no `Unit` property. The local systemd 255
interface documents that auxiliary argument as unused and transient timer
`Unit=` as unsupported; this ADR therefore never treats either as a unit-
definition or target-override API. Main re-reads timer,
action and operation objects, proves the tombstone still absent, CASes lifecycle
`static_action_loaded_inactive -> armed_not_invoked` only through
`deadline_action_arm_transition_v1`, consuming the already committed accepted
timer-start manager-result hash, then CASes the release gate to `inert_armed`
through `candidate_release_transition_v1`. Main keeps that `RefUnit` reference through static
install/property attestation, lifecycle CAS, timer reply reconciliation and the
armed proof. It may call `UnrefUnit(s) -> ()` only after the timer's exact
non-activating dependency is active and attested or after ordered failure
closure has retained every lifecycle/manager observation. `OllamaEvidenceController` is a logical
authority inside the already registered main process, not another process or
manager effect; no controller PID, pidfd, cgroup member or separate control
channel exists. It remains unable to disclose configuration or use a provider
socket while the gate is inert. Any create/attestation failure, broker failure
or main loss closes and proves that inert unit; it never proceeds to candidate
release. The `open` projection binds that exact armed gate, main authority and
logical-controller plan hash. A later
candidate effect is usable only through the release snapshot and effect-timing
contract; an out-of-order effect is failure evidence, not proof of prevention.

Partial-state recovery is closed. Failure before operation creation uses the
registered no-resource/rejection rules. After operation creation, any failure
closes the inert unit. Failure before static action load seals `not_created` and
proves the deterministic instance absent; failure after an authenticated static
load but before timer arm seals `static_action_loaded_inactive`; every branch
from capability-only through pending/ready source commits the matching exact
credential cleanup proof and calls `UnrefUnit` only after the retained
projections exist. If main dies, the connection-owned reference drops automatically.
Recovery then uses the exact manager journal and stable object censuses: a
proven accepted/armed timer is canonical `armed_not_invoked`; no committed load
or timer and exact instance absence is canonical `not_created`; a previously
committed `static_action_loaded_inactive` lifecycle remains historical and is
paired with the exact post-ref-drop unload observation rather than being
rewritten as `not_created`. None of these absence branches invents an action
InvocationID, terminal result or fire. An
acknowledged timer rejection proves the timer absent while preserving that exact
inactive static instance; an accepted timer must reach `armed_not_invoked` or an
exact retained failure lifecycle. A timer naming another action, an action not
derived from the installed template, a nonempty auxiliary array, a lost D-Bus
reply or any unclassifiable partial state is cleanup-unproven and keeps the
launch lock closed; it never causes a second create or timer rearm.

The primary deadline authority is the PID1-owned transient timer, not the
operation service. Its frozen recipe represents the trigger as the exact
systemd D-Bus `OnBootUSec` boot-monotonic value `timer_on_boot_usec`, with exact
`WakeSystem=yes`, `AccuracyUSec=timer_accuracy_usec`,
`RandomizedDelayUSec=0`, `Persistent=no` and `RemainAfterElapse=yes`. Its
deterministic same-basename service resolution, rather than a transient `Unit`
property, targets the exact deadline action instance. The timer transaction also pins the
explicit non-activating PID1 relationship
`Requisite=<deterministic operation service>` plus
`After=<deterministic operation service>`. It has no `Wants`, `Requires`,
`BindsTo` or `PartOf` edge. The authenticated property snapshot must contain
the operation member exactly once in each complete frozen `Requisite` and
`After` set, including any exact PID1-implied members; an unexpected, missing or
duplicate member fails. The custody proof must show that loading/starting this
timer neither starts nor restarts the already-existing operation, while the
relationship keeps PID1's operation reference through main D-Bus loss. The
snapshot must also show the corresponding `OnBoot` entry, `WakeSystem=true`,
exact `AccuracyUSec`, `RandomizedDelayUSec=0`, `Persistent=false` and
`RemainAfterElapse=true` on the same boot. `NextElapseUSecMonotonic` is recorded
but is **never** directly equated to the lease's `CLOCK_BOOTTIME` scalar.

The frozen `OllamaTimerClockObservationV1` has exactly `format`, `phase`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`,
`execution_owner_epoch`, `linux_boot_id`, `timer_unit_name`,
`deadline_timer_invocation_id`, `timer_properties_hash`, `wake_system`,
`boottime_before_ns`, `monotonic_before_ns`,
`next_elapse_usec_monotonic`, `monotonic_after_ns`, `boottime_after_ns`,
`offset_lower_ns`, `offset_upper_ns`,
`converted_trigger_boottime_lower_ns`,
`converted_trigger_boottime_upper_ns`, `read_duration_ns`, `uncertainty_ns` and
`observation_hash`. `format` is exactly
`worldforge_ollama_timer_clock_observation_v1`; phase is only
`awake_pre_suspend`, `suspend_resume_post_wake` or `pre_release`.

One observer performs the noninterleaved sequence
`B0=clock_gettime(CLOCK_BOOTTIME)`,
`M0=clock_gettime(CLOCK_MONOTONIC)`, the authenticated PID1
D-Bus property read, `M1=clock_gettime(CLOCK_MONOTONIC)`, then
`B1=clock_gettime(CLOCK_BOOTTIME)`. It records
`offset_lower_ns=B0-M0`, `offset_upper_ns=B1-M1`, converts the returned
finite non-sentinel integer microseconds into the inclusive boottime interval
`[next_elapse_usec_monotonic*1000+offset_lower_ns,
next_elapse_usec_monotonic*1000+offset_upper_ns]`, sets
`read_duration_ns=B1-B0`, and sets uncertainty to the interval width. Checked
arithmetic, same boot, monotonic `B0<=B1`, `M0<=M1`,
ordered `offset_lower_ns<=offset_upper_ns`, `WakeSystem=true` and the exact timer
properties are mandatory. Clock samples, durations, converted trigger values,
tolerances and deadlines are integer nanoseconds; the D-Bus elapse and all
`*_usec` values are integer microseconds. Offset bounds are signed 64-bit
nanoseconds: the lower bound may be negative because `B0` precedes `M0`; it is
never clamped or rejected merely for that reason. Both converted trigger bounds
must remain nonnegative after checked signed arithmetic. A suspend may increase
the offset, so a pre-suspend interval is never reused after resume.

The entire converted interval must lie inside the planned
`timer_on_boot_usec*1000 +/- timer_clock_conversion_tolerance_ns` window, and
its uncertainty must not exceed `timer_clock_uncertainty_limit_ns`. The guard
and planned-window arithmetic may not underflow or overflow; otherwise the
timer is unusable. The guard uses checked units and must exceed conversion
tolerance, uncertainty limit, accuracy, enforcement latency and safety margin
under the exact inequality
`deadline_guard_usec*1000 > timer_clock_conversion_tolerance_ns +
timer_clock_uncertainty_limit_ns + timer_accuracy_usec*1000 +
max_enforcement_latency_usec*1000 + timer_safety_margin_ns`. Every term is a
nonnegative signed-64-bit integer and both sides use checked nanosecond
arithmetic. The custody proof requires paired
`awake_pre_suspend`/`suspend_resume_post_wake` observations from a sacrificial
run whose resume is proven strictly before the guarded trigger, so both reads
have one finite next elapse. A separate sacrificial run suspends across the
trigger to test wake/action latency. Every actual operation requires a fresh
`pre_release` observation.

This is an evidence-backed logical cutoff, not a nanosecond or hard-real-time
guarantee. The separately sacrificial proof must live-prove that
`WakeSystem=yes` selects suspend-aware `CLOCK_BOOTTIME_ALARM` behavior for the
exact kernel/systemd recipe, exercise awake expiry and
suspend-before-trigger/resume-after-trigger, and record converted trigger
interval, timer activation, tombstone commit, stop request and domain-empty
boottimes. It establishes a conservative observed trigger/enforcement-latency
bound only for those pinned bytes. Conversion uncertainty, D-Bus latency,
coalescing or enforcement outside the bound, wake failure, missing suspend
observation, or ordering that overlaps the logical cutoff yields
`deadline_race_indeterminate` after any possible effect and no usable evidence;
it never becomes a future timing guarantee.

The deadline action is the frozen, installed static-template PID1 oneshot
instance outside the operation cgroup. Its exact code-owned helper binary/hash, fixed
argv, credential and narrow Store port may address only the deterministic
operation-unit object and bound tombstone key. It first obtains the exact
`compare_and_fire_deadline_v1` result; only then does it ask PID1 to kill the
operation MainPID when present, stop the unit in either `activating` or `active`,
and force-kill residual control-group members. Its action invocation/result are
retained and correlated to the operation terminal. The attested installed
template fixes `Type=oneshot`, `RemainAfterExit=yes`, `Restart=no` and
`CollectMode=inactive`; the timer reaches the already loaded instance only by
its exact same-basename implicit target and
its `StartTransientUnit` auxiliary array is empty. Successful helper exit remains loaded as `active/exited` until
ordered cleanup rather than depending on main's D-Bus reference.
After helper termination,
the narrow port and exact system-manager observer re-read the same retained
invocation/result and tombstone and idempotently commit
`append_deadline_action_terminal_v1`; main reconciles that exact lifecycle hash
before the systemd terminal projection. A crash after the fire transaction
leaves the durable `fire_committed_pending_terminal` state; it is resolved only
on the same boot by the phase-bound action append before its finalization
deadline or by the fenced current recovery owner at/after that deadline. After
a boot transition it is never resolved into an action terminal; the immutable
pending source is represented only by the reboot-abandonment projection after
current-boot cleanup. The timer and
action remain loaded only until the retained systemd terminal and exact action
lifecycle projections are durably committed; their subsequent closure precedes
the cleanup fixed-point projection.

The operation service therefore exists only inert before the timer/action pair
is armed; candidate release, not operation creation, is the guarded effect. A
release request is one StudioStore transaction that requires state
`inert_armed`, current execution-owner state `owned` and epoch, no tombstone or
recovery fence at the exact lease key and current
`CLOCK_BOOTTIME < deadline_boottime_ns`, then CASes to `released`. The deadline
action's fire transaction serializes against this release CAS only: a fire that
wins produces `fired_before_release`; a release that wins permits the action to
later produce `fired_after_release`. No fired or recovery-fenced state can return
to released.

The broker does not repeat those Store reads. Main obtains a fresh atomic
`OllamaEvidenceReleaseGateSnapshotV1` for each configuration disclosure,
fork/exec, listener effect and request send; the broker verifies only that
directional HMAC snapshot and measures the matching
`OllamaEvidenceOperationEffectTimingV1`. The release/tombstone/fence CAS cannot
atomically serialize an effect in another process, so this ADR makes no claim
that old-epoch configuration, fork, listener or request effects are physically
prevented. Their evidence is usable only if every admission/enter/return and
causal observation time is strictly below the snapshot expiry, logical cutoff,
any tombstone and any recovery fence. A request additionally requires the exact
full byte count and first/last same-clock capture. Any effect at/after a boundary,
an interval spanning it, stale owner epoch/snapshot, partial request or ordering
that cannot be proved during enforcement latency deterministically records
`deadline_race_indeterminate`; after any possible disclosure/fork/listener/send
it produces no usable scenario evidence and is never retried. It may retain
`clean_before_send` only when zero request bytes and cleanup are independently
proven; after any possible send it carries
`indeterminate_after_possible_send`. Full later PID1 cleanup does not repair the
timing failure.

A retry or ACK loss after a positively identified successful create for the
same lease returns the same operation, timer, action, gate, tombstone state,
trigger and invocations; it cannot reset/rearm,
replace a unit or restore 600 seconds. A boot-ID change expires all of them.
Exact transient `OnBoot`/`WakeSystem` semantics, suspend/resume behavior,
inert-to-release serialization, and action kill in both `activating` and
`active` must be live-proven; otherwise execution is unavailable.

`RuntimeMaxUSec` is separately computed as the integer floor of positive
`remaining_ns / 1000`; a sub-microsecond remainder is expired. It and the
broker's own boottime check are defense-in-depth only. Because
`RuntimeMaxUSec` is relative to service activation, neither is accepted as the
persisted absolute-deadline authority. If PID1 reports that any exact unit
already reached an incompatible terminal or collected state, the create
operation is never repeated; the attempt enters cleanup/recovery.

The transient operation-service property snapshot is exact and includes `Type=exec`,
`ExitType=main`, `KillMode=control-group`, `SendSIGKILL=yes`, `Restart=no`,
`RemainAfterExit=no`, `CollectMode=inactive`, an empty `SuccessExitStatus`
extension, `Delegate=yes`, `(TasksMax, variant t, 512)`,
`(LimitNOFILE, variant t, 4096)`,
`(LimitNOFILESoft, variant t, 4096)`, the computed `RuntimeMaxUSec`, and the custody policy's
exact finite `TimeoutStopUSec`, plus the exact `StandardInput=fd`,
`StandardInputFileDescriptor` UNIX-FD and encrypted broker-ready credential
properties above. The frozen unit recipe and property-snapshot document both
carry the exact `limits_hash`; the native launcher reattests that service and
runner hard/soft rlimits equal its `process_rlimit_nofile`. `TasksMax=512`
is separately reattested as the kernel thread-plus-process ceiling; the 31
outer process identities remain a distinct complete PID/start census and are
never inferred from `TasksCurrent`. `Type=notify`, `NotifyAccess`, notify sockets and readiness
environment are forbidden; readiness is solely the authenticated BrokerReady
record and its deadline. Its cgroup contains the broker and the nested
candidate subgroup. The subgroup retains its own `cgroup.kill` for
broker failure; failed-main/deadline custody kills the entire
broker-plus-candidate unit. `CollectMode=inactive` deliberately retains a
failed unit. The main authority holds the exact unit reference while live, and
the still-loaded timer's exact non-activating PID1 `Requisite` plus `After`
relationship to the deterministic operation service is the mandatory
persistent reference through the armed-timer offline path. It survives loss of
main's D-Bus connection without starting/restarting the operation; main's
separate operation-service `RefUnit` is only a live-path defense and never
satisfies offline retention.
While projecting an
invoked action, the narrow action port may additionally hold `RefUnit` for the
operation and action, but releases it only after the lifecycle/terminal CAS.
Neither that transient reference nor the timer dependency may be removed before
the terminal projection is acknowledged.

After a semantic scenario result and candidate-subgroup cleanup/result handoff,
the broker always exits the reserved nonzero sentinel 125, including after a
successful scenario. Exit 125 is absent from `SuccessExitStatus`, so PID1 marks
the unit failed and kills any residual control-group member. No semantic result
uses exit 0. Main-loss uses reserved exit 124; a broker-detected custody failure
uses reserved exit 126. Other exit codes, signals, watchdogs, timeouts and
manager failures remain distinct crash terminal classes and cannot impersonate
any sentinel. A deadline action is classified only by its exact retained
timer/action invocation plus the operation terminal. Normal semantic completion
does not call `StopUnit` in place of the sentinel contract. Every broker exit,
including a crash or signal, therefore leaves the operation in exact
`ActiveState=failed` with a non-success `Result` under `CollectMode=inactive`;
an inactive/successful operation terminal is never acceptable custody evidence.

The pre-timer main-loss window is closed by the same invariant. If main's
descriptor-198 endpoint disappears after the operation/broker exists but before
the timer transaction commits, broker exits sentinel 124 without releasing the
candidate. PID1 kills the group and retains the failed operation under
`CollectMode=inactive`. Before static instance load the lifecycle is exact
`not_created` and timer/action identities are absent; after authenticated static
load it is exact `static_action_loaded_inactive`, the timer remains absent and
the inactive action is retained until its lifecycle/terminal absence projection
and ordered closure. A surviving live main proves this with
the retained broker pidfd; a restarted/offline recovery authority uses the
authenticated retained failed operation. A missing/collected/nonfailed unit or
lost terminal observation leaves cleanup unproven rather than wedging into a
fabricated timer-retention path.

PID1 terminal `Result`, `ExecMainCode`, `ExecMainStatus`, `ActiveState`,
`SubState`, invocation and property bytes are read from the retained unit and
CASed as `worldforge_ollama_evidence_systemd_terminal_v1` before
`ResetFailedUnit`, any retention-releasing `UnrefUnit`, timer/action reset or
collection. The already-journalled static-action reference handoff to an
attested armed timer is not retention-releasing. No such reset,
unref or collection is permitted before StudioStore acknowledges that exact
projection. ACK loss re-reads the same retained failed object. Missing or
changed terminal evidence leaves cleanup unproven and the launch lock closed.

The broker has a mandatory authenticated main-loss lease channel whose main end
has no surviving duplicate. A candidate launch observation is unusable unless
pre-existing live evidence proves
that main endpoint loss/HUP makes the broker stop accepting work and exit with
the fixed main-loss status 124, and that this MainPID exit makes systemd fail
the service, retain its terminal result, and kill every remaining control-group
member under `KillMode=control-group`. The lease monitor plus those PID1 unit
semantics are one mandatory composite owner-death contract; neither half is
sufficient alone. The candidate uid receives neither cgroup control descriptors
nor escape authority.

Those semantics are never destructively self-proved by an Ollama evidence run.
They require a separate frozen `OllamaEvidenceCustodyProofV1` with exactly
`format`, `linux_boot_id`, `systemd_pid1_identity_hash`,
`systemd_binary_version_hash`, `kernel_identity_hash`, `custody_policy_hash`,
`operation_lease_policy_hash`, `candidate_profile_hash`,
`candidate_recipe_policy_hash`, `limits_hash`, `broker_recipe_hash`,
`native_single_thread_broker_policy_hash`,
`owner_liveness_observer_observation_hash`,
`main_loss_lease_policy_hash`, `deadline_timer_recipe_hash`,
`deadline_action_recipe_hash`, `deadline_action_store_policy_hash`,
`candidate_release_policy_hash`,
`deadline_tombstone_policy_hash`, `timer_property_snapshot_hash`,
`static_action_install_observation_hash`,
`static_action_load_observation_hash`,
`timer_empty_auxiliary_transaction_observation_hash`,
`operation_stdin_fd_delivery_observation_hash`,
`broker_ready_observation_hash`,
`deadline_action_lifecycle_observation_hash`,
`deadline_action_store_port_observation_hash`,
`wake_suspend_resume_observation_hash`,
`timer_clock_observation_set_hash`,
`timer_enforcement_latency_observation_hash`,
`release_race_observation_hash`, `sacrificial_fixture_hash`,
`activation_kill_observation_hash`, `active_kill_observation_hash`,
`main_loss_kill_observation_hash`, `pre_timer_main_loss_observation_hash`,
`timer_nonactivating_retention_observation_hash`,
`terminal_retention_observation_hash`,
`unit_gc_retention_observation_hash`,
`static_action_ref_lifetime_observation_hash`,
`broker_single_thread_observation_hash`,
`broker_thread_creation_unavailable_hash`,
`broker_concurrent_launch_rejection_hash`,
`fork_safe_launcher_observation_hash`, `key_vault_observation_hash`,
`child_fd_census_observation_hash`, `fork_window_observation_hash`,
`same_boot_broker_loss_cleanup_observation_hash`,
`spawn_handoff_boundary_observation_set_hash`,
`cleanup_proof_hash` and `observed_at`. `format` is exactly
`worldforge_ollama_evidence_custody_proof_v1`. A bounded code-owned sacrificial
fixture contains only the broker and fixed non-provider child: no Ollama
binary, model, prompt, project data, provider socket or candidate request. It
separately proves timer expiry during activation, timer expiry while active,
awake and suspend/resume wake/latency behavior, action firing at every
inert/check/release boundary, the immutable installed action template/helper,
static instance load-without-start, timer-primary transaction with an exact
empty auxiliary array, operation stdin-FD delivery and HMAC BrokerReady,
main-end loss, sentinel/crash retention, every one of the five action lifecycle
states,
pre-timer main loss, the exact LoadUnit -> RefUnit -> attest/CAS ->
timer-or-close -> UnrefUnit lifetime and PID1 collection boundaries, timer-to-operation
`Requisite`/`After` persistence and
operation-unit retention after main D-Bus death until terminal CAS. It
deliberately drops main's operation-service `RefUnit`/connection and proves that the relationship
does not activate/restart the operation and that PID1 GC does not collect the
failed operation;
it also proves the exact narrow deadline-action Store port remains authenticated
and can commit the sacrificial tombstone/terminal after that main loss; only the
later ordered timer/action closure permits collection. It also proves
the exact native launcher, DONTFORK/DONTDUMP key vault, blocked-signal/no-callback
fork window, exact one-TID native broker, concurrent-launch rejection and
closed child-FD census against the fixed non-provider child. It kills that
broker at every child-spawn-to-pidfd-Offer-to-Acceptance boundary and proves the
same-boot retained-systemd cleanup mode below,
plus fixed-point cleanup under the exact systemd/kernel/custody/profile hashes. The
authorization, operation lease and
`open` projection all bind the exact proof hash and revalidate it before launch.
The actual provider-evidence operation only consumes that proof; it never kills
its own main process to create it. No matching custody proof exists today, so
the logical controller cannot release or launch a candidate.

Authenticated handoff is owned only by an exact construction-created,
identity-registered `OllamaEvidenceHandoffAuthority`. Its class, root owner and
full immutable method snapshot are registered; copies, subclasses,
`object.__new__` instances, owner/root swaps and method/serializer drift are
rejected. Main first proves the broker through the exact PID1 MainPID,
invocation, unit/cgroup, executable hash, PID/start tuple and newly retained
pidfd, verifies the exact HMAC BrokerReady/fd0-to-198 observation, and verifies
the current exact one-TID native-broker observation above.
Only then does this authority generate one 32-byte kernel-CSPRNG HMAC key
bound to the exact attempt/lease/execution-owner epoch and deliver it once to
that proven broker over the pre-created local
`SOCK_SEQPACKET|SOCK_CLOEXEC` custody channel at descriptor 198 in each process.
Before either endpoint may receive any Offer, Acceptance or key material, its
owner must set `setsockopt(SOL_SOCKET, SO_PASSCRED, 1)` and attest
`getsockopt(SOL_SOCKET, SO_PASSCRED)==1` on that exact socket identity. Missing,
late, reset or substituted `SO_PASSCRED` closes the channel with no handoff
effect.
This is a one-operation-use key: it authenticates only that attempt's bounded
Offer/Acceptance chain and is never reused for another attempt, lease or chain.
The key ID is lowercase SHA-256 of the 32 bytes. The key exists only in the
exact main/broker DONTFORK/DONTDUMP key-vault mappings, is never argv,
environment, file, Store, artifact or log
content, never enters the logical controller's scenario-data objects or
service/runner memory, and is zeroized after
process closure proves that no further descendant handoff can occur and the
final handoff-chain hash is durably committed. No pre-proof key or configuration
delivery is allowed. An abort closes every arrival/source duplicate and
zeroizes both key copies before custody completion; missing zeroization proof is
cleanup-unproven rather than a reusable key.

Descriptor 198 accepts only one frozen wire registry. Every datagram begins
with the same 88-byte big-endian `Descriptor198RecordHeaderV1`: eight ASCII
bytes `WF46D198`, unsigned 16-bit version 1, unsigned 16-bit `record_code`,
unsigned 64-bit `channel_sequence`, unsigned 32-bit `payload_length`, 32 raw
bytes `prior_record_hash` and 32 raw bytes `payload_hash`, followed by exactly
`payload_length` bytes. `payload_hash` is SHA-256 over those exact bytes;
`record_hash` is the exact `descriptor_198_record_hash` formula above over ASCII
`worldforge-ollama-descriptor-198-record-v1`, one NUL byte, the 88 header bytes
and payload. Sequence zero names 32 zero bytes; every later header increments by
one and names the exact prior record hash. Record code, payload format and
current protocol state must agree before payload decoding.

The complete registry is:

| Code | Payload/discriminator | Maximum payload bytes | Direction/ACK |
|---:|---|---:|---|
| 12 | `worldforge_ollama_broker_ready_v1` | 4,096 | broker -> main; code 1 is its acceptance |
| 1 | `handoff_key_seed_v1` fixed binary | 168 | main -> broker |
| 2 | `worldforge_ollama_handoff_key_acceptance_v1` | 2,048 | broker -> main, ACK code 1 |
| 3 | `worldforge_ollama_evidence_custody_handoff_offer_v1` | 8,192 | role-defined sender -> receiver |
| 4 | `worldforge_ollama_evidence_custody_handoff_acceptance_v1` | 8,192 | reverse, ACK code 3 |
| 5 | `worldforge_ollama_release_gate_snapshot_v1` | 16,384 | main -> broker |
| 6 | `worldforge_ollama_release_gate_snapshot_acceptance_v1` | 8,192 | broker -> main, ACK code 5 |
| 7 | `worldforge_ollama_candidate_configuration_offer_v1` | 73,728 | main -> broker |
| 8 | `worldforge_ollama_candidate_configuration_acceptance_v1` | 8,192 | broker -> main, ACK code 7 |
| 9 | `worldforge_ollama_broker_operation_result_v1` | 24,576 | broker -> main |
| 10 | `worldforge_ollama_broker_control_ack_v1` | 8,192 | main -> broker, ACK code 9 or 11 |
| 11 | `worldforge_ollama_broker_terminal_v1` | 8,192 | broker -> main, then code 10 |

Code 12 is necessarily channel sequence 0, has zero prior-record hash and uses
only the separate one-use broker-ready HMAC key defined above. Main's valid code
1 at sequence 1, whose prior-record hash names that exact Ready, is the sole
Ready acceptance; no unauthenticated readiness state exists. Broker retransmits
only byte-identical code 12 while waiting. Main lookup returns the already
created byte-identical code 1 without generating/reinstalling another handoff
key. An identical Ready retry remains lookup-only until code 2 is committed;
changed Ready bytes, or any Ready after code 2/later state, close the channel.

Code 1 payload is exactly raw 32-byte attempt ID, authorization hash and lease
hash, one unsigned 64-bit owner epoch, raw 32-byte key ID and raw 32-byte key,
in that order. `key_id=SHA256(raw key)`; the receive iovec writes the final 32
bytes directly into the pre-attested key-vault page without an intermediate
serialization buffer. The frozen code-2
`OllamaEvidenceHandoffKeyAcceptanceV1` has exactly `format`, `domain`, `version`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`,
`execution_owner_epoch`, `seed_record_code`, `seed_channel_sequence`,
`seed_record_hash`, `seed_payload_hash`, `key_id`, `accepted_boottime_ns`,
`sender_principal`, `receiver_principal` and `authentication_hash`. `format`,
`domain` and `version` are exactly
`worldforge_ollama_handoff_key_acceptance_v1`,
`worldforge-ollama-handoff-key-acceptance-v1` and integer 1; principals are
exactly `ollama_evidence_broker_v1 -> studio_main_v1`;
`seed_record_code=1`, `seed_channel_sequence=1`, and code 2 occupies outer
channel sequence 2. Seed record/payload hashes must equal the exact accepted
code-1 header and payload, so the key Acceptance names one offer identity.

Its `authentication_hash` is HMAC-SHA256 with the received raw key over ASCII
`worldforge-ollama-handoff-key-acceptance-v1`, one NUL byte and the bounded
canonical JSON document with only `authentication_hash` omitted. Unknown keys,
another discriminator/version/domain/principal/attempt/authorization/lease/
epoch/seed/key or noncanonical bytes are replay or substitution. Main must
validate and register this exact Acceptance before code 3. If its reply is lost,
an identical code-1 record retransmitted at sequence 1 is reconciled by
`(attempt_id, operation_lease_hash, execution_owner_epoch, seed_record_hash,
key_id)` and returns the byte-identical code-2 record at sequence 2 without
reinstalling the key or advancing either chain. Main likewise treats an
identical code-2 duplicate as lookup-only; changed bytes or either duplicate
after a later accepted record close the channel and enter custody cleanup.
Codes 3-11 use only their already frozen payload schemas and
HMAC/subprotocol chains; their local `sequence` never replaces the channel
sequence.

Every endpoint receives with `recvmsg(MSG_CMSG_CLOEXEC)` after its exact
`SO_PASSCRED=1` proof. Every record requires exactly one
`SOL_SOCKET/SCM_CREDENTIALS` cmsg matching the bound peer and returned
`msg_flags=MSG_EOR` exactly. `MSG_TRUNC`, `MSG_CTRUNC`, `MSG_OOB`,
`MSG_ERRQUEUE`, a missing `MSG_EOR` or any unknown flag/cmsg is terminal
protocol failure. `SCM_RIGHTS` is forbidden for codes 1, 2, 4-12; code 3 has
exactly one rights cmsg with one FD only when its HandoffOffer declares
`descriptor_count=1`, and otherwise has none. Surplus bytes, cmsgs, FDs,
credentials, record types, wrong direction/peer, over-limit length,
payload/header hash drift, sequence gap/replay or either channel/subprotocol
chain mismatch closes the channel and enters custody cleanup. ACK loss
retransmits the identical record at the same channel sequence and returns the
already committed identical ACK; it never advances either chain or repeats an
effect. No other descriptor-198 format or unframed byte is permitted.

Each logical role uses an exact two-phase Offer then Acceptance; receiver-assigned
descriptor numbers can never authenticate their own transfer. Frozen
`OllamaEvidenceHandoffOfferV1` has exactly `format`, `domain`, `version`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`, `custody_policy_hash`,
`custody_proof_hash`, `execution_owner_epoch`, `execution_owner_hash`, `key_id`,
`sequence`, `prior_acceptance_hash`,
`sender_principal`, `receiver_principal`, `role`, `role_ordinal`,
`descriptor_count`, `descriptor_kind`, nullable `sender_fd_number`,
`expected_descriptor_flags`, `expected_status_flags`,
`logical_descriptor_fingerprint`, nullable `systemd_object_path`, nullable
`systemd_invocation_id`, nullable `pid`, nullable `start_time`, nullable
`executable_hash` and `authentication_hash`. `format`, `domain` and `version`
are exactly `worldforge_ollama_evidence_custody_handoff_offer_v1`,
`worldforge-ollama-evidence-handoff-offer-v1` and integer 1. It contains no
arrival or custody-slot number. `descriptor_count` is zero only for a handle
role and one for an `SCM_RIGHTS` role. `offer_hash` is not a field: it
is lowercase SHA-256 of the complete authenticated canonical Offer bytes.

Frozen `OllamaEvidenceHandoffAcceptanceV1` has exactly `format`, `domain`,
`version`, `attempt_id`, `authorization_hash`, `operation_lease_hash`, `key_id`,
`execution_owner_epoch`, `execution_owner_hash`, `sequence`, `offer_hash`,
`prior_acceptance_hash`, `sender_principal`,
`receiver_principal`, `role`, `role_ordinal`, `receiver_socket_identity_hash`,
`receiver_passcred_snapshot_hash`, `peer_pid`, `peer_uid`, `peer_gid`,
`recvmsg_flags`, `cmsg_census`, `arrival_fd_numbers`, nullable
`custody_fd_number`, `observed_descriptor_flags`, `observed_status_flags`,
`descriptor_identity_hash`, `validation_snapshot_hash`,
`accepted_boottime_ns` and `authentication_hash`. `format`, `domain` and
`version` are exactly `worldforge_ollama_evidence_custody_handoff_acceptance_v1`,
`worldforge-ollama-evidence-handoff-acceptance-v1` and integer 1. The census and
arrival fields are bounded ordered arrays of the actual `recvmsg` result;
handle roles use exact empty arrays. `acceptance_hash` is not
a field: it is lowercase SHA-256 of the complete authenticated canonical
Acceptance bytes.
Each `cmsg_census` element has exactly `index`, `level`, `type`, `data_length`
and `fd_count`; `arrival_fd_numbers` lists the received integers in control-data
order. `recvmsg_flags` is the exact returned integer bitmask, and the peer
fields are the kernel-supplied `SCM_CREDENTIALS`, not sender assertions. For
every valid Acceptance, `recvmsg_flags` is exactly the integer value of
`MSG_EOR`; any other bit or missing `MSG_EOR` is invalid under the outer record
registry.

Both frozen serializers emit exactly the keys above in order, require built-in
bounded scalars/arrays and explicit canonical JSON `null`, and reject unknown
keys or noncanonical encodings. Each authentication value is lowercase
HMAC-SHA256 over its exact ASCII domain, one NUL byte and the canonical document
with only `authentication_hash` omitted. Sequence 0 has
`prior_acceptance_hash` equal to 64 zeroes; each later Offer names the exact
previous `acceptance_hash`, and its Acceptance repeats that value and binds the
exact `offer_hash`. Neither handoff payload schema has a `payload_hash` field;
the outer descriptor-198 record header always has its separately defined raw
payload hash. Logical descriptor fingerprint, Offer hash and Acceptance
census/identity hashes have the closed meanings above.

The closed order and custody slots are:

| Sequence/role | Descriptor or handle | Main custody slot |
|---|---|---:|
| 0 `deadline_timer_handle` | exact timer object path/invocation, no FD | `null` |
| 1 `deadline_action_handle` | exact action object path/invocation, no FD | `null` |
| 2 `operation_unit_handle` | exact operation object path/invocation, no FD | `null` |
| 3 `broker_pidfd` | exact retained broker pidfd | 200 |
| 4 `candidate_cgroup_kill_fd` | exact subgroup `cgroup.kill` | 201 |
| 5 `candidate_cgroup_events_fd` | exact subgroup `cgroup.events` | 202 |
| 6 `service_pidfd` | exact retained Ollama service pidfd | 203 |
| 7+ `runner_pidfd` | contiguous runner ordinal 0 through 28 | 224 + ordinal |

`logical_descriptor_fingerprint` is lowercase SHA-256 of one closed canonical
role document: a systemd handle binds role, manager identity, object path,
invocation and property hash; a pidfd binds role/ordinal, PID, start time,
executable, cgroup and pidfd-info hashes; a cgroup FD binds role, mount ID,
device/inode, canonical relative cgroup path, access mode and file-identity hash.
No pathname or PID alone is a fingerprint.

Roles 0-2 are main-to-broker zero-FD handle Offers; roles 3 onward are
broker-to-main and carry exactly one role FD. Those are the only permitted
`sender_principal`/`receiver_principal` pairs for their sequence. The offered
broker pidfd is compared to the independent temporary pidfd main used for
pre-key broker proof before it is accepted into slot 200.

The retained operation process limit is exactly 31 identities: broker, service
and at most 29 runners. The logical controller is the main-process authority
and consumes no process/pidfd slot. Before an FD receive, main fills every reserved custody
slot with an owned `FD_CLOEXEC` reservation under the handoff lock. Each
receiver reattests `SO_PASSCRED==1`, calls `recvmsg(MSG_CMSG_CLOEXEC)`, and
rejects `MSG_TRUNC`, `MSG_CTRUNC` or
any result other than exact `MSG_EOR`; wrong peer credentials; a missing, extra,
duplicate or unknown control message; the wrong `SCM_RIGHTS` count; duplicate
FDs/roles; and any surplus payload. An FD Offer requires exactly one
`SOL_SOCKET/SCM_CREDENTIALS` item and one `SOL_SOCKET/SCM_RIGHTS` item containing
one FD. A zero-FD Offer requires the exact credential item and no rights item.
Every rejected arrival is closed with no slot or chain effect.

For a valid FD Offer, `MSG_CMSG_CLOEXEC` must already mark the arrival
`FD_CLOEXEC`; main atomically relocates it with `dup3(..., reserved_slot,
O_CLOEXEC)`, validates the role-specific logical fingerprint and live identity,
then closes the arrival FD. Pidfds permit no `O_APPEND`, `O_ASYNC` or
`O_NONBLOCK`; `cgroup.kill` is write-only and `FD_CLOEXEC`; `cgroup.events` is
read-only and `FD_CLOEXEC`; the custody channel is blocking, sequenced and
`FD_CLOEXEC`; all other descriptor/status flags are zero. Only after exact
peer/attempt/lease, census, slot, flags, PID/start/executable or systemd-handle
validation does the receiver emit the canonical HMACed Acceptance. The broker
keeps every offered source FD open and performs no descendant transition until
it validates that Acceptance; only then may it close its source duplicate.

The initial Acceptance chain through `candidate_cgroup_events_fd` is required
by `open`; service and runner Acceptances extend that chain only after the committed
`released` gate, and the final scenario envelope
binds the last `acceptance_hash`. On ACK loss, the sender retransmits the exact
same Offer and logical descriptor without advancing or closing. Receiver lookup
by `(attempt_id, operation_lease_hash, execution_owner_epoch, sequence,
offer_hash)` returns the exact
committed Acceptance; any duplicate arrival is independently censused,
fingerprint-validated and closed without changing the reserved slot. Changed
Offer bytes, descriptor identity, chain or peer are replay attacks and rejected.
A surplus FD/role, missing or gapped runner ordinal, reordered sequence, chain
drift, wrong slot/flag, truncation, message mutation, stale PID/start, copied
authority or owner swap is rejected. No descendant enters an authorized
lifecycle transition until its exact Acceptance is verified.

The logical controller shares main's lifetime and has no independent loss or
channel state. Broker loss makes systemd/main kill the whole unit; main loss is handled by the proven lease
monitor and PID1 unit contract; the persisted boot-scoped deadline is enforced
by the independent PID1 timer/action pair. RuntimeMax and broker checks remain
defense-in-depth only. A systemd/PID1 authority that is unavailable, has any
detected manager reload/generation change, loses the operation/timer/action
unit, invocation or terminal result, or lacks the exact bound custody proof
yields `unavailable` before send only after cleanup is proven, otherwise
indeterminate; after possible send it is indeterminate. The launch lock stays
closed.
PID1/host loss is a Linux
reboot path identified by boot-ID change, not an uncovered ephemeral-manager
path. Boot-ID change expires the attempt immediately and permits cleanup/recovery
only; it never permits unit recreation or scenario execution.

The frozen `OllamaEvidenceBootTransitionOwnerDeathProofV1` has exactly `format`,
`attempt_id`, `authorization_hash`, `stored_attempt_projection_hash`,
`stored_execution_owner_epoch`, `stored_execution_owner_hash`,
`stored_execution_owner_generation`, nullable `stored_operation_lease_hash`,
`stored_linux_boot_id`, `current_linux_boot_id`,
`current_boot_id_source_identity_hash`, `current_boot_id_read_hash`,
`current_kernel_identity_hash`, `current_systemd_pid1_identity_hash`,
`observer_identity_hash`, `expected_source_store_revision` and `observed_at`.
`format` is
exactly `worldforge_ollama_boot_transition_owner_death_proof_v1`; both boot IDs
are canonical Linux UUIDs and must differ. The stored ID comes only from the
expected durable owner/lease projection; the current ID comes from one
authenticated read of the code-owned Linux boot-ID source under the bound
kernel/PID1 observer. This proves that the old boot-scoped process/pidfd/unit
and socket authorities cannot still be live; device/backend reset is accepted
only after the separate current-boot zero-context/work census below. It grants
no raw PID or reconstructed-handle authority and says nothing about persistent files.

One expected-owner StudioStore CAS may use that exact proof to construct a
`reboot_abort_v1` `RecoveryFenceDocumentV1`, increment the owner epoch, install
a new-boot recovery owner whose distinct
`boot_transition_owner_death_proof_hash` names it, terminalize each mutable
registered release gate, preserve every already fired/recovery-fenced gate and
pending/terminal lifecycle as an immutable source, invalidate action
capabilities and all old-boot snapshots/effects before inspection.
It is the only recovery acquisition without a same-boot cutoff document. No
old evidence interval can be ordered onto the new clock, so the entire scenario
is non-evidence. Missing or equal boot IDs, a stale stored owner/revision,
manager/kernel mismatch or incomplete proof leaves the lock closed.

Cleanup proof has exactly six modes:

Normal semantic cleanup first makes the broker finish candidate-subgroup
cleanup, hand off the content-free semantic result and exit sentinel 125. Main
then waits for PID1 to kill residual members and retain the failed operation
unit. Failure/recovery cleanup instead uses only the already retained operation,
subgroup and system-manager authorities; an exact idempotent deadline action or
manager kill may force the same terminal state. Raw PID signalling is never a
fallback. For any created operation, its cgroup and device work become empty,
then the exact deadline-action lifecycle and retained systemd terminal
projections are CASed while the operation and every created timer/action object
remain loaded; `not_created` instead binds exact absence. Only
after those CASes may main stop/reset/unref the timer and static action instance and
record their exact closure hash. Only then may it reset/unref the already
projected failed operation and record its exact inactive-or-absent unit closure
plus cgroup-empty hash; the retained failed terminal hash remains immutable.
It then CASes the cleanup fixed-point projection referencing the already
committed terminal hash, action-lifecycle hash and both closure hashes.
Timer/action/operation retention is not required after those closure
observations, and none may be recreated for the lease. The Studio lock remains
held until the cleanup proof and the joint `proven` recovery/`terminal` owner
publication complete.

- `no_candidate_resources_v1` applies to `consumed_no_resources` before a lease
  is persisted, or to a **same-boot** `opening` attempt before the first manager
  effect. After an unequal-boot observation it is allowed only in the first,
  null-lease case; an `opening` projection already has a persisted lease and
  must use `reboot_abort_no_evidence_v1`. It requires the closed
  zero-allocation journal below, no lifecycle before a lease or exact
  `not_created` afterward, no operation,
  timer/action, broker/service/runner process, cgroup, scratch child,
  socket/listener/IPC, capture handle or device context, and no pidfd/closure
  inference.
- `manager_transaction_rejected_no_resources_v1` applies only when the first
  authenticated operation-service `StartTransientUnit` call was rejected and
  the exact rejection document below proves PID1 allocated no unit, job, cgroup,
  process, socket, scratch child, capture handle or device context. A rejected
  timer/static-action sequence cannot use this mode because the inert
  operation already exists.
- `live_main_pidfds_v1` requires retained broker and every candidate pidfd to be
  terminal, the committed retained-failed systemd terminal projection, then the
  authorized post-projection operation reset with unit inactive/absent plus its
  cgroup removed or `populated 0`, candidate subgroup empty, exact
  deadline-object closure, listener/IPC closure, device cleanup proof, observer
  drain, wire-buffer zeroization/unmapping and scratch/cache/log/root removal.
- `same_boot_retained_systemd_domain_v1` applies only while main remains the
  proven live owner in the lease boot but the broker died or a service/runner
  child crossed any spawn-to-pidfd-Offer-to-Acceptance boundary without a
  complete main-held pidfd set. Main uses the already retained exact operation
  unit/invocation and authenticated system-PID1 control-group kill/terminal
  authority, never the missing pidfd or a PID scan. The observation binds the
  last accepted handoff hash, exact failed boundary, pre-kill unit/cgroup member
  census, retained failed terminal, post-kill unit inactive/absent and cgroup
  removed or `populated 0`, listener/IPC closure, device cleanup, observer drain
  and owned-sink removal. Any member outside the exact unit/candidate subgroup,
  missing retained terminal or incomplete census leaves cleanup unproven.
- `offline_systemd_v1` is used after main loss or restart. It replaces the now
  unavailable per-pidfd conjunct with the committed terminal projection read
  from the authenticated **system** manager. Its retention source is either the
  armed timer's exact loaded, non-activating `Requisite`/`After` relationship or
  the exact pre-timer failed operation retained under `CollectMode=inactive`;
  main's lost D-Bus reference is never enough. It first commits that exact
  retained failed terminal, then requires the authorized reset and operation
  unit inactive/absent plus cgroup removed or `populated 0`, deadline-object closure, exact
  listener/IPC closure, device cleanup proof, observer evidence where retained,
  and the same scratch/log removal. It never reconstructs pidfds or signal
  authority.
- `reboot_abort_no_evidence_v1` is used only after the exact unequal-boot proof
  and reboot fence above. It never requires or reconstructs an old PID1
  terminal, pidfd, cgroup or device observation. In the new boot it instead
  exhaustively re-audits the deterministic operation/timer/action names and
  jobs, the exact old numeric listener tuple and local IPC names, process and
  socket ownership, and every declared device/runtime context. It also opens
  the configured scratch parent through a fresh `openat2` dirfd with exact
  `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`, verifies its identity and the attempt
  child name against the journaled parent/name manifest without pretending the
  old dirfd survived, removes every journaled scratch/cache/capture/log child
  without following links, and proves the root and every World Forge-owned sink absent.
  A reused name/listener, unexpected device context, inaccessible or lost
  census, unjournaled child or failed scrub keeps recovery pending and the lock
  closed.

The corresponding frozen `OllamaEvidenceRebootAbortV1` has exactly `format`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`,
`source_execution_owner_epoch`, `source_execution_owner_hash`,
`execution_owner_epoch`, `execution_owner_hash`, `recovery_fence_hash`,
`boot_transition_owner_death_proof_hash`, `stored_linux_boot_id`,
`current_linux_boot_id`, `source_attempt_state`, nullable
`preexisting_scenario_evidence_hash`, nullable
`preexisting_final_clean_hash`, nullable `preexisting_recovery_hash`,
`evidence_envelope_present`, `current_systemd_manager_identity_hash`,
`deterministic_unit_names_hash`, `unit_job_absence_hash`,
`process_socket_listener_ipc_absence_hash`, `device_context_absence_hash`,
`observer_identity_hash`, `observer_capture_hash`, `observer_loss_count`,
`journaled_scratch_manifest_hash`, `scratch_scrub_hash`,
`scratch_absence_hash`, `persistent_secret_sink_absence_hash`,
`public_durable_provider_content_absence_hash`, `result_class`,
`provider_evidence_present`, `provider_receipt_present` and `observed_at`.
`format` and `result_class` are both exactly
`worldforge_ollama_reboot_abort_no_evidence_v1`; boot IDs differ,
`observer_loss_count` is zero, `evidence_envelope_present=false` and
`provider_receipt_present=false`. `provider_evidence_present` is true if and
only if `preexisting_scenario_evidence_hash` is non-null; that hash names an
immutable private pre-reboot ScenarioEvidence and never evidence created by
this observation. A non-null final-clean hash requires that scenario hash and
`source_attempt_state=final_clean`; a non-null recovery hash must match the
source attempt's already committed pending/proven state. All other
state/nullability combinations follow the exhaustive eligibility table above.
All absence observations occur in the authenticated current boot and bind the
old deterministic lease names/tuple. The document cannot carry an old terminal
result, protocol result, usage, provider body, evidence envelope or receipt;
its optional hashes are content-free historical references only.

The frozen `OllamaEvidenceZeroAllocationJournalV1` has exactly `format`,
`attempt_id`, `authorization_hash`, nullable `operation_lease_hash`,
`execution_owner_epoch`, `execution_owner_hash`, `release_gate_id`,
`store_registration_hash`, `manager_effect_count`,
`process_count`, `cgroup_count`, `pidfd_count`, `socket_listener_ipc_count`,
`scratch_child_count`, `capture_handle_count`, `device_context_count`,
`pid1_absence_observation_hash`, `scratch_absence_observation_hash` and
`observed_at`. `format` is exactly
`worldforge_ollama_evidence_zero_allocation_journal_v1`; every count is exactly
zero. Its owner fields name the source owner at the zero-allocation boundary,
not a later recovery epoch. The Store registration hash may name only the content-free nonce/gate,
tombstone/recovery key, deadline-action capability ID/nonce/key/method hashes
and `not_created` lifecycle records. Any attempted or
unknown manager/resource effect makes this mode invalid rather than being
rounded down to zero.

The frozen `OllamaEvidenceManagerTransactionRejectionV1` has exactly `format`,
`attempt_id`, `authorization_hash`, `operation_lease_hash`,
`execution_owner_epoch`, `execution_owner_hash`, `linux_boot_id`,
`systemd_manager_identity_hash`, `method`, `primary_unit_name`,
`auxiliary_unit_names`, `transaction_request_hash`, `dbus_serial`, `error_name`,
`error_payload_hash`, `reply_bytes_hash`, `reply_received_boottime_ns`,
`reply_journal_event_id`, `reply_journal_hash`,
`reply_journal_committed_boottime_ns`, nullable `job_path`,
`manager_effect_attempted`,
`allocation_observed`, `manager_event_capture_hash`, `manager_event_loss_count`,
`first_absence_census_hash`, `manager_quiescence_barrier_hash`,
`second_absence_census_hash`, `deterministic_unit_absence_hash`,
`job_absence_hash`,
`cgroup_absence_hash`, `process_socket_scratch_device_absence_hash` and
`observed_at`. `format` is exactly
`worldforge_ollama_manager_transaction_rejection_v1`; method is exactly
`StartTransientUnit`; the primary name is the deterministic operation service;
and auxiliary names are the exact empty array. `manager_effect_attempted` is
true, `allocation_observed` is false, `manager_event_loss_count` is zero and
`job_path` is canonical null.

The rejection is eligible only when the authenticated PID1 D-Bus peer, manager
boot identity, serial, exact reply bytes, error name/payload and transaction
request all match, and main durably journals those reply bytes immediately
after receipt and before any other manager/resource effect. The Store event
binds the reply-receipt and journal-commit boottimes with
`reply_received_boottime_ns <= reply_journal_committed_boottime_ns`. A Store ACK-loss lookup may
return that exact journal because the caller still holds the exact reply bytes;
the connection-local D-Bus serial is never a replay or re-read handle.

The exact pre-armed PID1 manager/cgroup/process event capture must span the call
and both absence censuses with zero loss. The two censuses are byte-identical
complete enumerations of the deterministic operation/timer/action names, all
PID1 jobs and the deterministic cgroup/process/socket/scratch/capture/device
classes. Between them, the observer drains its event queue and performs one
authenticated read of the frozen PID1 Manager `Version` property; that reply,
serial, manager boot identity and property snapshot are the exact
`manager_quiescence_barrier_hash`. Both direct `GetUnit` absence replies, both
`ListUnitsByPatterns`/`ListJobs` results and the zero-event interval are bound.
Only this journaled rejection plus stable exhaustive absence qualifies for
`manager_transaction_rejected_no_resources_v1`.

A lost or ambiguous D-Bus reply, transport disconnect before the reply is
journaled, or unknown acceptance state is the closed failure code
`manager_transaction_unknown`. It is never reconstructed from a serial and
never qualifies for either no-resource cleanup mode. If an exact allocated unit
is later found in the same boot, it is cleaned only through
`live_main_pidfds_v1`, `same_boot_retained_systemd_domain_v1` or
`offline_systemd_v1`; mere same-boot later absence
cannot prove that no transient effect occurred, so recovery remains pending.
After an authenticated boot change, only `reboot_abort_no_evidence_v1` may
resolve it, with no newly created provider evidence or reconstructed old
result. A preexisting private ScenarioEvidence remains historical input and
must be fenced by eligibility abandonment. An
allocated job/unit, manager restart, partial census or any observed resource
also invalidates rejection mode. The attempted call is never misreported as the
zero-manager-effect `no_candidate_resources_v1` journal.

The frozen `OllamaEvidenceDeviceCleanupV1` has exactly `format`, `mode`,
`attempt_id`, `operation_lease_hash`, `backend_observation_hash`,
`observer_identity_hash`, `observer_binary_hash`, `observer_library_hash`,
`observer_version_hash`, `device_runtime_hash`,
`before_context_work_inventory_hash`, `after_context_work_inventory_hash`,
`attribution_policy_hash`, `closure_hash` and `observed_at`. `format` is exactly
`worldforge_ollama_evidence_device_cleanup_v1`; V1 `mode` is the sole literal
`cpu_only_no_device_v1`. It proves that after candidate exec the exact service
and runner descriptor censuses contain no character/block device FD except the
single inherited read-only `/dev/null` fd 0 bound as `stdin_null_v1`, and proves
zero accelerator-device FD/open/mmap/ioctl, accelerator library/runtime/
interface and attributable accelerator context/work. It does not claim zero
device-node FDs in the presence of that declared stdin role.
The before and after inventories are exact zero-attributable-context/work
observations from the read-only observer; this is not a generic claim that the
host has zero GPUs. `backend_observation_hash` names the exact CPU backend/file
closure, and `device_runtime_hash` names the exact no-device census schema and
result rather than an opened runtime. The access-policy hash pins every
observer input/interface.

`accelerator_observed_v1` is reserved for a future versioned policy and is
unavailable: it is not a V1 profile choice, device-cleanup mode, scenario input
or PASS value. Discovery of any accelerator library, device FD, mapping, ioctl,
runtime, context, queue, kernel or work item invalidates V1 evidence, triggers
retained-domain cleanup and keeps the launch lock closed unless the exact
CPU-only fixed point is independently proven. This ADR makes no GPU cleanup or
zero-GPU claim.

The frozen `OllamaEvidenceCleanupProofV1` has exactly `format`, `mode`,
`attempt_id`, `authorization_hash`, nullable `operation_lease_hash`, nullable
`lease_boot_id`, `observed_boot_id`, `execution_owner_epoch`,
`execution_owner_hash`, `source_execution_owner_epoch`,
`source_execution_owner_hash`, `retention_source`,
nullable `owner_cutoff_hash`, nullable `recovery_fence_hash`, nullable
`recovery_takeover_chain_hash`,
`systemd_manager_identity_hash`, nullable
`systemd_unit_name`, nullable `systemd_invocation_id`,
nullable `systemd_terminal_projection_hash`, nullable
`deadline_action_lifecycle_hash`, nullable
`deadline_credential_cleanup_proof_hash`, nullable `zero_allocation_journal_hash`, nullable
`manager_transaction_rejection_hash`, nullable `reboot_abort_observation_hash`,
nullable `evidence_eligibility_abandonment_hash`,
nullable `broker_loss_or_incomplete_handoff_observation_hash`, nullable
`retained_systemd_domain_observation_hash`,
`unit_inactive_observation_hash`, `cgroup_empty_observation_hash`, nullable
`pidfd_terminal_set_hash`, `listener_ipc_closure_hash`,
`deadline_objects_closure_hash`, nullable `device_cleanup_proof_hash`,
`observer_drain_observation_hash`, nullable
`http_wire_buffer_zeroization_hash`, `secret_zeroization_hash`,
`scratch_removal_hash` and `proved_at`.
`format` is `worldforge_ollama_evidence_cleanup_proof_v1`; `mode` is exactly
`no_candidate_resources_v1`, `manager_transaction_rejected_no_resources_v1`,
`live_main_pidfds_v1`, `same_boot_retained_systemd_domain_v1`,
`offline_systemd_v1` or
`reboot_abort_no_evidence_v1`. `retention_source` is exactly
`not_applicable_v1`, `live_main_pidfds_v1`,
`same_boot_operation_unit_v1`, `timer_requisite_after_v1` or
`operation_failed_collectmode_v1`. No-resource, manager-rejection and reboot
modes use `not_applicable_v1`; live mode uses `live_main_pidfds_v1`; same-boot
retained-domain mode uses `same_boot_operation_unit_v1`; offline mode uses
exactly one of the final two values and binds its corresponding authenticated
retention observation through the named systemd terminal projection's exact
`unit_gc_retention_observation_hash`. No-resource mode requires a
non-null zero-allocation journal, null manager-rejection/reboot/handoff/domain
hashes and null
unit/invocation/terminal/device/pidfd hashes; lifecycle is null before
`opening` and must name exact `not_created` after a lease exists. Live
mode requires null zero-allocation journal, manager-rejection, reboot, handoff
and retained-domain hashes plus the
terminal, action-lifecycle, device and pidfd-set hashes. Offline mode requires the same except that its
pidfd set is canonical JSON `null` and may not be inferred. Live, same-boot
retained-domain and offline modes bind the exact retained
numeric listener tuple, local IPC identities and scratch/log sink inventory.
Only no-resource mode may use a null lease before `opening`; its authenticated
PID1 and journal observations must prove no operation/timer/action create
result, cgroup, process, listener, device context or scratch child exists.
For its unequal-boot pre-lease branch, `operation_lease_hash` and
`lease_boot_id` are canonical null, `observed_boot_id` is the authenticated new
boot, cutoff is null, `recovery_fence_hash` names the exact reboot fence, and
`reboot_abort_observation_hash` remains null because no lease-scoped resource
ever existed. Under an unequal boot, any non-null lease switches exclusively to reboot mode
below.
Manager-rejection mode requires a non-null exact rejection hash, null
zero-allocation/reboot/handoff/domain/unit/invocation/terminal/device/pidfd hashes, exact
`not_created` lifecycle and the persisted lease; its absence hashes fill the
inactive/cgroup/listener/deadline/observer/scratch proof fields. Opening after
any allocated or unclassifiable manager effect and every `open` proof require
live, same-boot retained-domain or offline mode and the persisted lease/unit fields.
Same-boot retained-domain mode requires non-null exact broker-loss-or-incomplete-
handoff and retained-domain observations, the persisted same-boot
lease/unit/invocation,
terminal/action/device hashes, and null zero-allocation, manager-rejection,
reboot and pidfd-set hashes. Its cgroup/listener/deadline/observer/scratch fields
bind the exact fixed point above; a partial pidfd set is recorded only inside
the handoff observation and never promoted into `pidfd_terminal_set_hash`.
Reboot mode requires the persisted non-null lease, unequal
`lease_boot_id`/`observed_boot_id`, an exact non-null reboot-abort observation,
and null zero-allocation, manager-rejection, handoff/domain, old unit/invocation/terminal,
action-lifecycle, pidfd and device-proof hashes. Its inactive/cgroup/listener,
deadline-object, observer-drain, secret and scratch fields bind only the
reboot-abort document's authenticated new-boot absence/scrub observations;
they never reconstruct an old terminal or claim old per-process/device facts.
The eligibility-abandonment hash is null when mutable `opening|open` cleanup
must commit before abandonment. It is non-null only for the narrow immutable
`final_clean|failed_clean` plus pending-recovery transition, and then must name
the exact already committed abandonment whose attempt, BootTransition proof,
reboot fence and reboot-abort observation byte-match this proof. No other mode
or state may populate it.
When the old source pair is R6/R7, this cleanup proof does not consume or
rewrite its pending lifecycle and does not compare its old boottime deadline.
The cleanup proof must commit first; the exact
`OllamaDeadlineActionRebootAbandonmentV1` event then re-reads that proof,
reboot-abort observation, boot-transition proof and unchanged pair before any
failure terminal or unlock chain may proceed.
`source_execution_owner_epoch`/hash always match the operation lease, manager
rejection or source no-resource projection. `execution_owner_epoch`/hash name
the current cleanup authority: they are identical on normal cleanup and name
the atomically fenced incremented owner during recovery. Any missing or
unprovable source-to-recovery fence mapping invalidates the proof. Normal
same-owner cleanup requires the cutoff/fence/takeover fields null; same-boot
recovery cleanup requires the exact non-null cutoff and fence, plus a non-null
complete takeover-chain hash when the recovery epoch advanced more than once.
Reboot recovery instead requires a null cutoff and exact `reboot_abort_v1`
fence. Before any `OllamaEvidenceOperationLease` is persisted, the null-lease
`consumed_no_resources` branch pairs that fence with the exact zero-allocation
journal and a null reboot observation under `no_candidate_resources_v1`; it may
terminalize only `failed_clean` with `clean_no_launch` and no provider evidence,
receipt, `final_clean` or `observed_nonproduction` publication. Once a lease is
persisted, including `opening` before the first manager call, unequal boot must
use `reboot_abort_no_evidence_v1` and a non-null exact reboot-abort observation;
no no-resource assignment is permitted. Either branch releases the launch lock
only after its exact eligibility-abandonment CAS, cleanup proof and joint
recovery-proven/owner-terminal CAS. A previously sealed envelope is the sole
case with no abandonment and is never rewritten.
Any later takeover remains in the new boot and extends that exact fence chain.
`secret_zeroization_hash` proves closure and zeroization of every issued
handoff, derived release-snapshot/control and deadline-action capability key,
including each key-vault mapping and no-resource/rejected-manager paths; a
surviving/unknown copy keeps cleanup unproven. Reboot mode instead proves that
these keys were never persisted and that no current-boot process or owned sink
contains them; it makes no forensic claim about dead RAM.
`deadline_credential_cleanup_proof_hash` is null only when the zero-allocation
journal proves capability registration, credential-source registration and
every credential-file syscall never occurred. Once capability registration exists it is mandatory in every
normal, failure, recovery and reboot mode and must name the exact clean proof
whose attempt, lease, owner epoch, capability registration, source generation,
branch and boot relation match this outer proof. The outer proof cannot precede
it. A source path, FD, plaintext/key/ciphertext working copy or un-fsynced
parent left behind keeps cleanup unproven even when the candidate domain is
empty.
`http_wire_buffer_zeroization_hash` is null only when the zero-allocation
journal proves that neither anonymous wire mapping was ever created, and in
reboot mode where the old mappings cannot survive the authenticated boot
transition. Every same-boot path after either mapping was allocated requires
the exact non-null `OllamaHttpWireBufferObservationV1` observation proving the
full-process mapping census, continuous locks, any required native-parser
observation, complete-mapping `explicit_bzero`, zero census, `munlock`,
`MADV_DONTNEED` and unmap in that order; an `open` scenario always requires it.
A missing, file-backed, insufficiently locked, retained or unmapped buffer
keeps cleanup unproven.

No-resource and authenticated-manager-rejection modes prove zero allocation;
live, same-boot retained-domain and offline modes prove broker plus candidate
empty, zero attributable device work and closed deadline objects. Reboot mode proves only the exact new-boot
absence and persistent-sink scrub described above and creates no provider
evidence; its boolean truthfully reports an immutable preexisting
ScenarioEvidence when one exists.
Only then may recovery be `proven`.
Outside exact `reboot_abort_no_evidence_v1`, an authenticated boot transition
never substitutes for a required durable terminal projection or device proof.
Within that mode it replaces only non-surviving kernel/PID1 facts and still
requires complete new-boot name/listener/device absence plus disclosure-sink
removal; missing evidence leaves recovery unproven and the lock closed. Raw PID signalling,
process-name matching, `/proc`/inode scans and reconstructed handles never grant
signal authority.

Every recovery path first completes the owner-death/revocation or exact
unequal-boot proof and atomic epoch-bump/fence CAS above; a proven-live owner
duplicate returns state and does not enter this paragraph. A takeover of a crashed recovery owner first performs
the separately fenced recovering-to-recovering CAS and invalidates every old
recovery action. If a deadline-action lifecycle is
`fire_committed_pending_terminal` on the **same** boot, recovery permits only
its phase-bound terminal append strictly before the finalization deadline,
waits through that same-boot deadline, and thereafter finalizes it under the
current recovery epoch before continuing. With an unequal boot it performs
none of those comparisons or transitions: the pending lifecycle remains an
immutable source, current-boot reboot cleanup commits, and the exact
reboot-abandonment projection becomes the sole bridge to failure
terminalization. No other old-epoch write survives the fence.

Same-boot recovery from `consumed_no_resources` or `opening` before the first
manager call commits `no_candidate_resources_v1` from the closed zero-allocation
journal. Unequal-boot recovery may use that mode only from
`consumed_no_resources` before any lease was persisted; its immutable failure
code is `reboot_abort_no_evidence_v1` and it publishes no provider
evidence/receipt. An unequal-boot `opening` already has a lease and must instead
use `reboot_abort_no_evidence_v1` cleanup with its non-null reboot observation.
Same-boot recovery from the durably journaled authenticated rejection of the first
operation-unit call uses
`manager_transaction_rejected_no_resources_v1`; `manager_transaction_unknown`
can use neither branch. After boot change that persisted rejection/lease also
uses reboot-abort cleanup, never rejection mode. A fenced unequal-boot attempt
with a persisted lease uses only
`reboot_abort_no_evidence_v1`: it performs the new-boot audit and owned-sink
scrub above, then commits the eligibility-abandonment CAS before any
failure-terminal, recovery-proven or unlock transition. A mutable nonterminal
attempt writes immutable `failed_clean` with that exact failure code and
cleanup mode (`clean_no_launch` only when the durable old projection proves
release never occurred; otherwise `indeterminate_after_possible_send`). An
existing `final_clean`, `failed_clean` or `failed_cleanup_pending` remains
immutable and follows its exact row in the exhaustive table instead. It never
reconstructs a terminal/effect fact from residual scratch. If its old pair is
R6/R7, it first commits the
reboot-abandonment projection after cleanup and may write only the dedicated
`failed_clean` joint-transition row; an existing `failed_cleanup_pending`
attempt remains immutable and its pending recovery instead consumes the same
abandonment source. It writes no new ScenarioEvidence, evidence envelope,
private artifact, provider receipt, usage or protocol result and can never
become publication-eligible, `observed_nonproduction` or PASS. A ScenarioEvidence
or `final_clean` that predates reboot is retained only as an immutable source.
For a same-boot `opening` after any allocated/unclassifiable
manager effect or an `open`, recovery uses the persisted old-epoch unit
name/object path, timer/action names, lease hash, boot/deadline and authenticated
system manager to invoke the exact already-bound kill/terminal path
idempotently. It seals the lifecycle and terminal evidence while loaded, closes
timer/action, then seals the live/same-boot-retained/offline cleanup proof referencing those prior
hashes.

Once a cleanup proof exists, the attempt transition writes its immutable
`failed_clean` (or normal `final_clean`) terminal and exact `pending` recovery,
still naming the pre-terminal owner. The sole publication transaction defined
above then atomically changes that recovery to `proven` and that same owner to
`terminal`. There is no intermediate terminal owner and no later recovery CAS.
If cleanup proof does not exist, the attempt writes the one immutable
`failed_cleanup_pending` plus `pending`; the owner remains
fenced/`recovering` and the launch lock stays closed.

Once `failed_cleanup_pending` exists, recovery never writes another attempt
terminal: only its recovery projection may advance `pending -> proven|failed`.
When later cleanup succeeds, that `pending -> proven` and
`recovering -> terminal` are the same joint transaction; when recovery is
declared failed, no terminal owner or unlock is published.
ACK loss for Store CASes, handoff, a positively identified successful unit
creation, open, kill, terminal, recovery, lock release or artifact publication
is resolved by exact event/unit lookup and committed hashes. A lost D-Bus
create reply is instead `manager_transaction_unknown` under the closed rule
above and is never converted into an acknowledged rejection. The deterministic lease,
PID1-owned deadline timer/action, two-clock timer conversion, persistent
timer-to-operation GC retention, retained terminal contract, HMAC handoff,
release snapshots, execution-owner fencing, deadline-action Store capability,
native fork-safe launcher/key vault, device observer/cleanup closure, custody
proof, main-loss behavior, all created-resource cleanup modes and the reboot
abort path have not been live-proven on this host; the
no-resource/rejected-manager journals and narrow Store port also do not exist.
Therefore the logical controller cannot release or launch a candidate today.

### Bounded evidence-controller operation

`OllamaEvidenceController` is the sole scenario operation authority in this ADR
and is a logical, identity-registered, one-use authority executing inside the
already proven main process. It is not a process, child, cgroup member, pidfd
role or independently crashable principal. All controller-to-broker commands
use only the exact descriptor-198 registry: BrokerReady, handoff key seed/key Acceptance,
HandoffOffer/HandoffAcceptance, ReleaseGateSnapshot/SnapshotAcceptance,
CandidateConfigurationOffer/ConfigurationAcceptance,
BrokerOperationResult/BrokerControlAck and BrokerTerminal. There is no second
controller/broker socket, record type or handoff protocol. It remains
subordinate to the broker/main custody
authorities above and is **not**
a `ProviderAdapter`, runtime, catalog, selection, Harness worker or main-parent
gateway. It accepts only the exact identity-registered authorization already
bound to the committed `consumed_no_resources`, `opening` and `open`
projections for this operation; copies, subclasses, `object.__new__` instances,
owner swaps and replay cannot run.

One authorization selects exactly one facet/scenario from this ordered,
finite, code-owned v1 catalog; it cannot authorize a batch. Each row has a
distinct frozen facet-artifact type, and the generic scenario evidence embeds
exactly one matching facet artifact:

| Order | Facet ID | Scenario ID | Facet artifact ID | Exact operation |
|---:|---|---|---|---|
| 0 | `protocol_text` | `ollama_nonstream_text_success_v1` | `worldforge_ollama_protocol_text_evidence_v1` | Send the fixed request once; require one bounded terminal response and clean close. |
| 1 | `control_pre_send` | `ollama_pre_send_cancellation_v1` | `worldforge_ollama_control_pre_send_evidence_v1` | Launch, connect and prove the peer; cancel before the first request byte; prove cleanup. |
| 2 | `control_post_send` | `ollama_post_send_disconnect_v1` | `worldforge_ollama_control_post_send_evidence_v1` | Send the fixed request once; after `exact_runner_observed`, close at one second without accepting a terminal result. |

Request-sending scenarios use this exact canonical JSON body:

```json
{"keep_alive":0,"messages":[{"content":"Return exactly the ASCII token WORLD_FORGE_OLLAMA_EVIDENCE_V1 and nothing else.","role":"user"}],"model":"qwen3.6:27b","stream":false}
```

The code-owned request uses only `POST /api/chat`, exact `Host`, `Accept`,
`Content-Type`, `Content-Length` and `Connection: close` headers. A caller
cannot supply text, tools, context, system messages, images, model, options,
origin, endpoint, header, parser, facet, scenario, timeout or cancellation
point. It discloses no user or project data. This fixed non-sensitive probe
bounds the consequence of an observation failure; it does not make leakage
impossible. Any bounded error, status or framing probe requires a new finite
catalog revision with an exact non-sensitive request and a separate exact human
authorization; arbitrary fuzzing is forbidden.

Every scenario receives one fresh `0700` scratch root outside the Forge and
model roots, one custody-owned candidate subgroup, at most one
numeric-loopback connection, and no retry. The custody policy binds the retained
private scratch-parent dirfd and its identity; the attempt root is its exact
no-symlink child named by `attempt_id`, and the `open` projection binds that
root's full identity hash. The scenario plan carries the exact `limits_hash`:
the operation has a 600-second maximum duration on the persisted
`CLOCK_BOOTTIME` window, accepts at most 31 outer-operation process identities
(30 candidate identities including at most 29 runners) by complete PID/start
census, separately configures `TasksMax=512` for all cgroup threads and
processes, configures
`RLIMIT_NOFILE=4096` but accepts at most 256 open FDs per candidate process,
bounds the fixed request wire bytes and response headers to 64 KiB each and one
complete anonymous in-memory response wire image to 1 MiB, bounds cumulative
in-memory response receipt to 16 MiB,
and accepts at most 64 MiB of
scenario scratch inside the separately enforced 256 MiB quota.
Each scenario executes only its row. An early terminal response in the
post-send scenario means that cancellation was not exercised and that scenario
evidence is unusable; another scenario cannot fill the gap. Limit, overflow or
capture failure likewise makes only that scenario evidence unusable.

The `protocol_text` artifact binds only the exact request,
`request_send` effect-timing hash, observed response
status/headers/framing/body hash/terminal branch, observed usage counts and
clean close. The `control_pre_send` artifact binds the ordered operation-effect
timing-set hash, peer proof, proof of zero request bytes, close and zero-resource
cleanup. The `control_post_send` artifact binds the exact sent bytes,
`request_send` effect-timing hash, retained runner state, one-second close,
subsequent observed process/I/O transitions and the mandatory indeterminate
effect classification; it never claims provider cancellation. A facet artifact
cannot substitute for another row.

The private preterminal `worldforge_ollama_scenario_evidence_v1` binds the
authorization, declared facet/scenario, plan and `limits_hash`; its one exact facet-artifact hash;
controller/recipe/access/input/custody/operation-lease hashes;
broker/outer-scope/candidate-subgroup/handoff identities; exact process, peer,
runner and I/O transitions; exact fork-window observation and ordered
operation-effect timing-set hashes;
the content-free HTTP wire-buffer/zeroization observation, bounded wire hashes
and structural transcript metadata;
resource observations; ambient-sink catalog/observation-set hashes; egress/log
capture and loss counters; exercised branch;
all failures; and cleanup proof. It hashes no attempt terminal, recovery, owner
terminal or envelope. `scenario_evidence_sealed_v1` commits it as the sole
preterminal evidence target; `final_clean` binds that committed ScenarioEvidence
only. From that atomic terminal event onward the same immutable hash is
source-qualified `terminal_bound_v1`; it is not rewritten or resealed. After the
separate proven-recovery/terminal-owner joint transaction, the forward-only
`evidence_envelope_sealed_v1` event creates the envelope from the immutable
ScenarioEvidence, final attempt, proven recovery, terminal owner and cleanup
proof. No earlier projection hashes that envelope. "Evidence envelope complete"
means internally complete for that one declared scenario only; it never means
that the vendor protocol as a whole is known. No scenario claims an unexercised
behavior. The artifacts store no raw model output/log, are never public and
remain non-executable data. They retain no raw HTTP replay material.

Before normal cleanup, the controller closes its connection, seals only the
durable content-free ScenarioEvidence inputs and retains no artifact bytes.
The broker then kills and empties the candidate subgroup, authenticates the
content-free result handoff and exits sentinel 125; main waits for the retained
PID1 terminal, device and deadline-object fixed point, commits the validated
preterminal ScenarioEvidence through `scenario_evidence_sealed_v1`,
terminalizes the attempt/recovery/owner, then
seals the envelope and publishes the private artifact in separate forward-only
events by deterministic Store-only re-rendering. A main crash after cleanup and
before publication loses no required input. Failure/deadline
paths invoke the exact candidate or outer lease kill authority instead. A pidfd
permits role-specific observation or a graceful signal, but only the retained
subgroup/outer authorities establish cleanup. Publication does not release the
launch lock; only the terminal attempt's `proven` recovery does. Cleanup
uncertainty is indeterminate and can never yield usable evidence.

### Unavailable cloud-off evidence profile

The ambient unit can never satisfy this ADR: it lacks `OLLAMA_NO_CLOUD`, uses
`Restart=always`, has an ambient `PATH`, and is not launch-owned. The binary
also contains cloud proxy/recommendation code, including
`https://ollama.com/api/experimental/model-recommendations`.

The frozen static `OllamaCandidateExecutionProfileV1` has exactly `format`,
`production_eligible`, `installation_observation_hash`,
`binary_closure_hash`, `model_lock_hash`, `executable_realpath`,
`executable_hash`, `argv_policy_hash`, `environment_policy_hash`,
`model_root_policy_hash`, `numeric_loopback_policy_hash`, `account_name`,
`group_name`, `uid`, `gid`, `expected_groups`, `credential_policy_hash`,
`device_profile`,
`candidate_subgroup_policy_hash`, `pidfd_acquisition_policy_hash`,
`descriptor_policy_hash`, `access_policy_hash`,
`backend_device_inventory_policy_hash` and `profile_generation`. `format` is
exactly `worldforge_ollama_cloud_off_candidate_v1` and
`production_eligible` is the immutable literal false. It is an **unavailable
evidence target**, not executable authority. It contains no attempt, lease,
execution-owner epoch, operation subgroup, scratch root, selected origin,
launcher-policy, final argv/environment or final recipe hash.

`account_name` and `group_name` are exactly `ollama`; `uid`/`gid` are the
numeric identities bound by the installation observation, never portable
constants; and `expected_groups` is that observation's exact raw `Groups:` list
under the no-distinct-supplementary-group invariant. `device_profile` is
exactly `cpu_only_no_device_v1`. `backend_device_inventory_policy_hash` names
only the read-only observer inventory policy and grants the candidate no device
right. The executable realpath is `path4096`, its hash is the raw executable
digest, UID/GID/groups are `u53`, generation is exactly one, and every other
`*_hash` is a nonzero ordinary content reference to the named already-complete
observation/closure/policy. The document has no nullable value, is at most
32,768 canonical bytes, and any extra credential/device/production field is
rejected.

The Director decision and authorization independently bind this static profile
and the exact `OllamaCandidateRecipePolicyV1`. The pre-authorized launcher
policy binds those two static hashes one-way. Only after the operation lease,
candidate subgroup and scratch identities exist may main derive the final
`OllamaCandidateRecipeV1` defined above; that final recipe alone binds the
profile, recipe policy, launcher policy and operation-specific values. Neither
the profile, recipe policy, launcher, authorization nor lease hashes that final
recipe. The final environment must contain exact `OLLAMA_NO_CLOUD=1`; every
other key/value and the final argv, model-root identity, numeric-loopback
origin and uid/gid must be explicitly derived, bound and reported rather than
inherited, defaulted or invented. After launch and before connect, the
main-process logical controller and custody broker must live-prove and hand off
the exact service PID/start/pidfd, credential snapshot and all those facts. V1
admits only the exact CPU-only/no-device profile: a selected accelerator backend,
device open, device context or nonempty candidate DeviceAllow list is drift,
not an observation success. The current host has no such profile,
authorization, final recipe or evidence.

### Exact evidence access policy

The sole normative candidate-domain I/O allowlist is the final frozen
`OllamaEvidenceAccessPolicyV1`. Its subject begins only at the observed
successful candidate exec identity. The native launcher's earlier
`/proc/self/fd` open/census and temporary directory fd belong exclusively to
`OllamaEvidenceForkSafeLauncherV1`, are closed before exec, and are neither
candidate inputs nor candidate rights; the post-exec candidate census must not
contain that fd or path authority. Its exact ordered keys are `format`,
`policy_generation`, `production_eligible`, `installation_observation_hash`,
`binary_closure_hash`, `model_lock_hash`, `candidate_profile_hash`,
`candidate_recipe_policy_hash`, `ambient_sink_catalog_hash`, `read_inputs`,
`numeric_loopback_endpoints`, `local_ipc_entries`, `writable_entries`,
`ambient_sink_entries`, `candidate_device_rights`, `observer_device_rights`,
`process_rights`,
`fd_rights`, `network_rights`, `descriptor_198_record_codes`,
`native_wire_parser_policy_hash`, `limits_hash`, `timeout_limits`,
`capture_rules`, `privacy_rules`,
`cleanup_rules` and `failure_rules`. `format` is exactly
`worldforge_ollama_evidence_access_policy_v1`, generation is a positive
JavaScript-safe integer and `production_eligible` is the literal false. Every
named hash is lowercase 64-hex. The serializer accepts only built-in JSON
scalars, exact key order, canonical explicit nulls where declared, integer
values in their stated ranges and UTF-8 strings at most 4,096 bytes; it rejects
floats, bool-as-int, duplicate/unknown keys, duplicate ordinals, symlinks or
noncanonical paths. The whole canonical document is at most 524,288 bytes and
its content hash follows the global canonical-document rule. It is
non-executable data; no later section or implementation may restate, extend or
weaken it.

`read_inputs` contains 1 through 128 entries, each with exactly `ordinal`,
`input_kind`, `realpath`, `device`, `inode`, `mode`, `uid`, `gid`, `size`,
`sha256`, `required` and `access`. Ordinals are contiguous from zero; kind is
only `server_executable_v1`, `runner_executable_v1`, `shared_library_v1`,
`backend_candidate_v1`, `model_manifest_v1`, `model_blob_v1`, `config_blob_v1`,
`license_blob_v1`, `parameter_blob_v1`, `loader_runtime_file_v1`,
`observer_executable_v1`, `observer_library_v1`,
`wire_parser_executable_v1` or `wire_parser_library_v1`; every entry has
`required=true`, `access=read_only`, an absolute normalized realpath and exact
nonnegative stat scalars plus byte hash. An opened/mapped/executed input absent
from this list is policy drift, even when it is merely inventoried.

`numeric_loopback_endpoints` has exactly one entry with keys `ordinal`,
`endpoint_id`, `address_family`, `transport`, `numeric_address`, `port`,
`client_principal`, `server_principal`, `direction`, `dns_allowed`,
`proxy_allowed`, `redirect_allowed`, `external_route_allowed` and
`peer_attribution_policy_hash`. Its values are exactly ordinal 0,
`AF_INET`, `tcp`, `127.0.0.1`, a pre-authorized integer port in `1..65535`,
`studio_main_ollama_controller_v1`, `candidate_service_v1`,
`client_to_server_v1`, and four false booleans. `endpoint_id` is an independent
64-hex value
`SHA256(ASCII("worldforge-ollama-numeric-loopback-endpoint-v1") || 0x00 ||
"AF_INET" || 0x00 || "tcp" || 0x00 || "127.0.0.1" || 0x00 ||
decimal(port) || 0x00 || peer_attribution_policy_hash)`; it contains no
listener/process observation. A port collision or inability to prove the
exact accepted peer makes the authorized scenario unavailable, never a reason
to pick another port.

`local_ipc_entries` has zero through the exact
`candidate_local_ipc_entry_acceptance_max` contiguous entries from
`limits_hash`, each with exactly `ordinal`,
`ipc_kind`, `endpoint_identity_policy_hash`, `initiator_principal`,
`receiver_principal`, `candidate_domain_required`, `capture_required` and
`maximum_messages`. Kind is only `unix_stream_v1`, `unix_seqpacket_v1`,
`anonymous_pipe_v1` or `shared_memory_v1`; principals are only service/runner
identities in the candidate subgroup, both booleans are true, and the positive
message limit is at most 1,000,000. There is no wildcard path, abstract-socket
prefix or provider-independent IPC class.

`writable_entries` has exactly five ordered entries, each with exactly `ordinal`,
`sink_kind`, `path_derivation_policy_hash`, `parent_scratch_policy_hash`,
`required_mode`, `required_uid`, `required_gid`, `maximum_bytes`,
`content_class`, `cleanup_required` and `symlink_policy`. Their closed order is
`candidate_scratch_root_v1`, `candidate_runtime_dir_v1`,
`candidate_cache_dir_v1`, `declared_stdout_capture_v1`,
`declared_stderr_capture_v1`; byte limits are
positive and at most `scenario_scratch_acceptance_max_bytes` from `limits_hash`,
cleanup is true and symlink policy is `reject_all_v1`. Stdout/stderr are
`provider_content_sensitive_v1`, and directories are `container_only_v1`. The final
recipe derives their absolute paths beneath its exact custody-owned scratch
root; a derivation mismatch is not a new allowed sink. None of these entries is
an HTTP request/response capture, replay sink or evidence-artifact staging
path. All five are candidate operational directories/log endpoints only;
artifact publication has no scratch entry.

`ambient_sink_entries` has exactly seven entries corresponding ordinal-for-
ordinal to the bound `AmbientSinkCatalogV1`. Each contains exactly `ordinal`,
`sink_kind`, `catalog_entry_hash`, `observer_identity_hash`, `maximum_observed_bytes`,
`required` and `raw_content_durable_allowed`; kind/order are the seven literals
below, byte counts are finite, `required=true`, and
`raw_content_durable_allowed=false`. `candidate_device_rights` has exactly
`device_profile`, `systemd_device_policy`, `device_allow_entries`,
`inherited_character_device_roles`, `stdin_null_role`,
`device_node_open_allowed`,
`device_mmap_allowed=false`, `device_ioctl_allowed=false`,
`accelerator_runtime_allowed=false` and
`violation_action`. The first three values are exactly
`cpu_only_no_device_v1`, `closed` and `[]`; the inherited role array is exactly
`[stdin_null_v1]`; and the last four booleans are false with violation action
`evidence_unusable_and_cleanup_v1`.
`stdin_null_role` is a nested object with exactly `role`, `realpath`, `device`,
`inode`, `rdev`, `mode`, `uid`, `gid`, `fd_number`, `access_mode`,
`descriptor_cloexec`, `opened_by`, `opened_before_candidate_exec`, and
`candidate_open_allowed`. Its values are `stdin_null_v1`, `/dev/null`, exact
live-observed `u53` stat identity values with a character-device mode,
`fd_number=0`, `read_only`, false, `fork_safe_launcher_v1`, true and false in
that order. The broker-side construction-captured launcher opens and proves
the exact node before
`clone3` under `child_fd_policy_hash`, and the pre-exec child only inherits and
censuses it. The candidate receives only that already fixed read-only fd 0 and has no
authority to open it or any other device node. This sole inherited standard-I/O
character device is not an accelerator permission and does not weaken empty
`DeviceAllow` or the prohibition on every accelerator node, mapping, ioctl,
runtime, context and work item. `observer_device_rights` has exactly
`observer_principal="studio_device_census_observer_v1"`,
`observer_identity_hash`, `observer_library_closure_hash`,
`process_census_read_allowed=true`, `device_census_read_allowed=true`,
`candidate_device_open_allowed=false`, `device_control_allowed=false`,
`context_inventory_schema_hash`, `required=true` and
`observation_loss_limit=0`. The observer runs outside the candidate subgroup,
reads only the declared process/device census interfaces and cannot open or
control a device on the candidate's behalf.

`process_rights` has exactly `candidate_principals`, `allowed_spawn_edges`,
`setuid_allowed`,
`setgid_allowed`, `setgroups_allowed`, `capability_change_allowed`,
`ptrace_allowed`, `namespace_change_allowed`,
`cgroup_control_allowed`, `ambient_signal_allowed` and `unknown_descendant_action`.
The principals are exactly service then runner; the only spawn edge is
`candidate_service_v1 -> candidate_runner_v1`; the candidate/runner census
maxima come only from top-level `limits_hash`; all eight authority booleans are
false; unknown descendant action is
`evidence_unusable_and_cleanup_v1`. Broker launch/custody is outside this
candidate-domain object and remains governed by the lease.

`fd_rights` has exactly `candidate_role_set`,
`cloexec_required_roles`, `inheritable_roles`, `scm_rights_allowed`,
`descriptor_198_visible_to_candidate`, `surplus_action` and
`census_required_at_exec`. The ordered role set is exactly `stdin_null_v1`,
`stdout_owned_capture_v1`, `stderr_owned_capture_v1`, `read_input_v1`,
`numeric_loopback_listener_v1`, `numeric_loopback_accepted_peer_v1`,
`declared_local_ipc_v1`; the open-FD
acceptance maximum and process rlimit come only from top-level `limits_hash`,
all roles except exact stdio are CLOEXEC, inheritable roles are only the three
stdio roles, and `stdin_null_v1` must byte-match the nested
`candidate_device_rights.stdin_null_role`; both booleans concerning
rights/descriptor 198 are false, surplus
action is `evidence_unusable_and_cleanup_v1`, and exec census is true.

`network_rights` has exactly `new_socket_principals`, `allowed_endpoint_ids`,
`allowed_local_ipc_policy_hashes`, `dns_allowed`, `proxy_allowed`,
`redirect_allowed`, `external_route_allowed`, `raw_socket_allowed`,
`socket_capture_required`, `peer_correlation_required` and
`unexpected_socket_action`. New sockets are allowed only to the service and
runner roles needed by declared local IPC and the main logical-controller/
service roles necessary for the one numeric endpoint above; the exact ordered
principal array is
`[studio_main_ollama_controller_v1,candidate_service_v1,candidate_runner_v1]`; allowed
endpoint IDs contain exactly that endpoint ID; IPC hashes exactly match the IPC
entries; all five route/raw booleans are false, both capture/correlation
booleans are true, and unexpected action is
`evidence_unusable_and_cleanup_v1`. The complete candidate-domain socket census
must not exceed `candidate_socket_identity_acceptance_max` from `limits_hash`.

`descriptor_198_record_codes` is the exact ordered integer array
`[12,1,2,3,4,5,6,7,8,9,10,11]` and delegates discriminator, direction, HMAC,
payload maximum, cmsg and ACK behavior only to the frozen registry above.
`limits_hash` is exactly the non-null canonical `OllamaEvidenceLimitsV1` hash
bound by authorization, scenario, recipe, custody and unit; no nested or
caller-overridden resource-limit object exists. `timeout_limits` has exactly
`broker_ready_timeout_ns=5000000000`, `handoff_timeout_ns=5000000000`,
`connect_timeout_ns=5000000000`, `response_timeout_ns=300000000000`,
`observer_drain_timeout_ns=5000000000` and `cleanup_timeout_ns=60000000000`;
none extends or resets the lease deadline.

`capture_rules` has exactly `arm_before_candidate_launch=true`,
`process_capture=true`, `file_capture=true`, `network_capture=true`,
`local_ipc_capture=true`, `sink_capture=true`, `device_capture=true`,
`cover_all_descendants=true`, `complete_interval_required=true`,
`lost_event_limit=0`, `drain_before_cleanup_proof=true` and
`durable_capture_bytes_allowed=false`,
`http_wire_buffer_kind=anonymous_private_v1`,
`http_wire_buffer_mapping_flags=[MAP_PRIVATE,MAP_ANONYMOUS]`,
`http_wire_buffer_madvise_flags=[MADV_DONTDUMP,MADV_DONTFORK]`,
`http_wire_file_backing_allowed=false`,
`http_wire_mlock_required=true`, `http_wire_rlimit_memlock_check_required=true`,
`http_wire_locked_page_census_required=true`,
`native_zero_copy_parser_required=true`, `http_wire_zeroization_required=true`,
`http_wire_munlock_required=true`, `http_wire_unmap_required=true` and
`raw_http_replay_retention_allowed=false`. `privacy_rules` has exactly
`fixed_nonsensitive_probe_only=true`, `caller_text_allowed=false`,
`project_data_allowed=false`, `http_wire_in_memory_only=true`,
`http_wire_in_owned_scratch_allowed=false`,
`http_wire_in_any_file_allowed=false`, `raw_replay_retention_allowed=false`,
`provider_content_in_public_store_allowed=false`,
`provider_content_in_durable_store_allowed=false`,
`provider_content_in_receipt_allowed=false`,
`application_file_backing_created=false`,
`swap_while_locked_absence_claimed=true`,
`absolute_persistence_absence_claimed=false`,
`residual_host_memory_risk_acknowledged=true`,
`outside_catalog_host_leakage_absence_claimed=false`,
`staged_artifact_allowed=false` and
`deterministic_artifact_rerender_required=true`.

`cleanup_rules` has exactly `kill_candidate_subgroup=true`,
`kill_outer_operation_on_custody_failure=true`, `prove_domain_empty=true`,
`prove_listener_closed=true`, `prove_local_ipc_closed=true`,
`prove_device_fixed_point=true`, `zeroize_operation_keys=true`,
`remove_all_writable_entries=true`, `drain_capture=true`,
`allowed_cleanup_modes` equal to the exact ordered array
`[no_candidate_resources_v1,manager_transaction_rejected_no_resources_v1,live_main_pidfds_v1,same_boot_retained_systemd_domain_v1,offline_systemd_v1,reboot_abort_no_evidence_v1]`, and
`lock_release_requires_proven_recovery=true`. `failure_rules` has exactly
`pre_resource_class=clean_no_launch`,
`pre_send_with_proven_cleanup_class=clean_before_send`,
`post_possible_send_class=indeterminate_after_possible_send`,
`cleanup_unproven_class=indeterminate_cleanup_unproven`,
`policy_drift_action=evidence_unusable_and_cleanup_v1`,
`capture_loss_action=evidence_unusable_and_cleanup_v1`, `retry_allowed=false`,
`catalog_admission_allowed=false` and `availability=unavailable`. These nested
objects admit no extra key or alternate literal.

The remaining access paragraphs are non-normative consequences of that exact
document; they add no path, endpoint, role, right, sink, timeout or exception.

Its exact subject is every I/O operation by the service, runner and descendants
inside the custody-owned candidate subgroup, plus only the bounded
numeric-loopback/in-memory-wire I/O that the logical controller performs in
main for this scenario, until the cleanup fixed
point. All other main
control-plane I/O, the outer-scope custody broker, content-free deadline
action/narrow Store port and StudioStore projections are outside that subject
and are governed by the authorization/custody contracts above. The deadline
credential source is likewise a separately registered ciphertext-only trusted
control-plane sink governed exclusively by its source/cleanup schemas; it is
not a sixth candidate writable entry. The deadline action carries no provider content and has only its fixed kill target plus
two-method capability. The descriptor-198 main-to-broker channel is that sole
content-free custody/control channel. Its only payloads are BrokerReady,
the handoff key seed/key Acceptance, HandoffOffer/HandoffAcceptance,
ReleaseGateSnapshot/SnapshotAcceptance,
CandidateConfigurationOffer/ConfigurationAcceptance,
BrokerOperationResult/BrokerControlAck and BrokerTerminal records; it may never
receive a request, response or provider log. Neither the broker nor StudioStore
may receive provider content.

Read-only execution inputs are closed separately from writable disclosure
sinks. The authorization pins the server and runner bytes; every known shared
library/backend candidate; the model, config, license and parameter blobs; and
the system loader/runtime files by realpath, device/inode, size, mode and hash.
The model root is read-only. Runtime-selected CPU backend files are captured as
exact opens and mappings during the evidence run; they are inventory
observations, not pre-approval. An unknown, inaccessible or unrecorded input,
or any device/runtime interface access, makes V1 evidence unusable. A later
executable profile must independently review and pin the actually selected
backend closure; accelerator support needs a different versioned profile.

The same policy pins the cleanup observer's exact code-owned identity, binary,
library and version hashes; its read-only process/device census interfaces; its event
and context/work attribution schemas; and its armed interval, completeness and
zero-loss rules. These are observation inputs only, never device-control or
execution authority. An absent or unsupported exact observer makes evidence
execution unavailable rather than silently selecting a generic accelerator check.

The only candidate operational writable destinations are the custody-owned
scratch root and its fixed stdout/stderr log sinks. There is no controller
evidence scratch or staged-artifact destination. None is an HTTP wire capture
or raw replay destination. `HOME`,
temporary/runtime state and any provider cache are redirected into that scratch
recipe; a write to the model root, ambient home, system path or any undeclared
sink makes the evidence unusable. The main-owned durable private artifact store
is outside the candidate domain and accepts only the deterministic canonical
payload re-rendered from exact durable content-free projections after
fixed-point cleanup. No download or installation route is
allowed.

The access policy binds one frozen `AmbientSinkCatalogV1` with exactly `format`,
`installation_observation_hash`, `binary_closure_hash`, `model_lock_hash`,
`catalog_subject_policy_hash`, `entries`,
and `catalog_generation`. `format` is exactly
`worldforge_ollama_ambient_sink_catalog_v1`. It contains no access-policy,
candidate-profile, final-recipe or observation-set hash; the access policy
binds the completed catalog one-way. Each ordered
entry has exactly `ordinal`, `sink_kind`, `sink_identity_policy_hash`,
`observer_identity_hash`, `query_policy_hash`, `maximum_observed_bytes`,
`required`, `content_class` and `retention_policy_hash`. All entries are
required, byte limits are finite, and the closed order is:

1. `declared_stdout_capture_v1`;
2. `declared_stderr_capture_v1`;
3. `exact_operation_unit_journal_query_v1`;
4. `owned_scratch_metadata_v1`;
5. `exact_core_dump_metadata_query_v1`;
6. `declared_socket_observer_v1`;
7. `declared_device_observer_v1`.

`content_class` is only `provider_content_sensitive_v1` for entries 1-5 or
`content_free_observation_v1` for entries 6-7. The catalog observer records
only the bounded metadata defined below; that label never authorizes it to copy
sensitive sink bytes into a durable artifact.

The stdout/stderr and scratch entries bind only their exact owned paths under
the attempt root. The journal query is read-only and binds the exact boot ID,
unit name, invocation ID, cursor interval and journal namespace. Core-dump
metadata binds only the exact configured owned metadata paths plus the
read-only unit/PID/time query; it never asserts that every host dump mechanism
is enumerable. Socket and device entries bind only the declared code-owned
observers and their finite intervals. Each catalog observation records exact
query bytes/hash, result metadata hash, observed byte count, completeness and
loss count. Missing/inaccessible catalog entries, overflow or catalog capture
of raw provider content makes scenario evidence unusable.

Every provider log is `provider_content_sensitive`. World Forge creates no
path-backed, memfd, shared-memory or scratch sink for controller HTTP request
or response bytes: those bytes exist only in the bounded anonymous main-local
mappings, whose digests/structured observations are sealed before mandatory
zeroization and unmapping. Candidate stdout/stderr remain operational provider
log sinks, not wire-capture authority; the candidate recipe must not enable
request-debug logging, and no unproven environment value is credited as proof
that the provider cannot echo bytes. If the provider does echo any HTTP request or
response byte into a declared log, journal, core path or other owned file, the
scenario is unusable and that sink is scrubbed rather than retained as replay
material. Raw provider content never enters a World Forge-owned public or
durable Store, receipt or EventLog; the private durable artifact binds only
hashes of the buffer/capture configuration, declared interval,
process/socket/IPC events, loss counters, sink inventory and content-free
scenario result. Observe-only custody cannot prevent an ambient system journal, kernel
or security logger, core-dump facility, proxy, packet/socket observer or other
host-owned sink from capturing bytes. Acceptance enumerates only the exact
AmbientSinkCatalog entries above; an outside-catalog sink is residual host risk,
not a discoverable completeness gate and never claimed absent. Cleanup can
scrub only declared World Forge-owned sinks and zeroize the controller mappings;
it cannot undo leakage or claim
outside-catalog bytes never existed. Every public projection remains
content-free.

For this pre-execution evidence run, the policy's only provider-bearing
network/IPC endpoints are the retained logical-controller-to-server
numeric-loopback connection and retained local server-to-runner IPC whose
provider endpoints belong to the custody-owned domain. The policy requires
capture and identity correlation of every endpoint. Descriptor 198 is bound by
the operation lease/custody policy, is outside the candidate subgroup, carries
only BrokerReady, the handoff key seed/key Acceptance, HandoffOffer/HandoffAcceptance,
ReleaseGateSnapshot/SnapshotAcceptance,
CandidateConfigurationOffer/ConfigurationAcceptance,
BrokerOperationResult/BrokerControlAck and BrokerTerminal records, and is not a
distinct controller process channel.
Any external/nonlocal socket, unowned or inaccessible IPC endpoint, undeclared
writable sink, lost event or incomplete capture makes the envelope unusable.
This policy observes rather than prevents leakage; only the fixed non-sensitive
probe bounds the possible disclosure.

### Protocol and causal peer attribution

Static disassembly proves a `POST /api/chat` route and candidate JSON tags:
request `model`, `messages`, `stream`, `format`, `options`, `tools`, `think`,
`keep_alive`, `logprobs`, `top_logprobs`; response `created_at`, `message`,
`done`, `done_reason`, duration/evaluation counts and `error`. These static
candidates establish no protocol facet. Each scenario artifact records only the
observations defined by its frozen facet type. The v1 `protocol_text` scenario
can record its method/path, exact request bytes, returned status/headers,
observed JSON or NDJSON framing, response structure, terminal branch, body hash,
usage counts and close. The pre-send scenario establishes no request or response
semantics. The post-send scenario records its disconnect observation but cannot
claim cancellation. Error branches, unknown-field behavior, size boundaries,
`stream:true`, tools, images and every other unexercised behavior remain
`unavailable`. Request-sending v1 scenarios are text-only, `stream:false`,
reject tools/images and take the fixed request only from controller code; no
generic HTTP tunnel exists.

Adjacent listener snapshots do not authenticate a peer. The controller must
follow this closed state machine before any request byte:

```text
unavailable -> service_domain_retained -> socket_connected
 -> accepted_peer_correlated -> pre_send_revalidated -> effect_possible
```

`service_domain_retained` means main has received and ACKed pidfds for the exact
service PID/start and every then-observed descendant through the authenticated
custody handoff. It binds uid/gid, cgroup, executable, cmdline, root/cwd,
environment, descriptors and sockets. After a fresh numeric-loopback connect,
`accepted_peer_correlated` must match the connected local/remote tuple and
socket identity to the exact accepted peer FD held by that retained process
domain. `pre_send_revalidated` repeats the exact process, cgroup, socket and
peer proof against the endpoint pinned by `OllamaEvidenceAccessPolicyV1`. A race,
rebind, inaccessible candidate, missing attribution or
identity change is `unavailable` before send and indeterminate after any
possible send. Current host permissions/evidence have **not** proved this causal
correlation, so execution remains unavailable.

Every before-send `unavailable` result is valid only after any connected socket
is proven closed and candidate-subgroup, outer-scope, scratch and capture cleanup
reaches the fixed point under the canonical access policy. A rejection before
resource acquisition proves the same zero-resource state only through
`consumed_no_resources` recovery and manager absence proof. Any cleanup
uncertainty is indeterminate instead.

### Authorized runner lifecycle

The only valid scenario-aware lifecycle graph is:

```text
stopped -> server_ready -> stopped
server_ready -> load_pending -> exact_runner_observed -> turn_active
 -> unload_pending -> server_ready -> stopped
```

The pre-send scenario takes the first branch and cannot claim runner behavior.
Request-sending scenarios take the second. A cold-load descendant is expected
only in `load_pending`, so its appearance is not itself drift. Each new or
replacement descendant must be causally linked to the retained service/cgroup,
identified by PID/start plus its own main-retained, handoff-ACKed pidfd, and
bound to the exact executable, selected shared-library/backend closure and model
lock before `turn_active`. Service and every runner also require the exact
recipe-matching `CredentialSnapshotV1`; a credential-changing syscall or UID,
GID, Groups, capability or `NoNewPrivs` mismatch is descendant drift. V1 may
select only an observed CPU backend and must retain the no-device census; an
accelerator backend or device context is never an authorized runner state.
Replacement outside its authorized transition, an inaccessible or surplus
descendant, or any identity/library/model drift fails closed. `unload_pending`
ends only after `keep_alive` behavior and the exact runner exit/baseline are
observed. No current evidence proves which exact model blob the runner loaded;
that missing causal proof blocks any later executable profile.

### Finite egress, telemetry and log evidence

The evidence profile is always `egress_enforcement=not_enforced` and
`telemetry_status=observed_not_enforced`. Its finite capture window begins with
process, network and log observers armed before candidate launch and ends only
after the declared scenario outcome, its required runner/unload/baseline state,
candidate-subgroup and outer-scope kill/empty proof, observer drain and zero
lost-event counters. It must cover the service and every descendant. Any lost
event, inaccessible descendant, uncorrelated process or interval gap fails only
that scenario evidence. Deadline expiry is an outer-lease kill and failed
attempt, never a graceful scenario result.

Every captured I/O event must validate against the one canonical
`OllamaEvidenceAccessPolicyV1` hash above; this section adds no destination or
sink. A policy violation makes the scenario unusable. Even a scenario-valid
finite capture cannot prove future zero egress or zero telemetry.

Pre-send cancellation is clean only when no byte may have been sent, the
connected socket close is proven, observation handles are closed, and process
domain/capture cleanup proves the broker-plus-candidate custody fixed point and
exact baseline. Its config/fork/listener timings must still be
`strictly_before_all_fences`, and its `request_send` timing must be exact
`no_effect`; otherwise it is not clean evidence. From the first send attempt,
disconnect, deadline, malformed
response, cancellation, service/runner drift or uncertain close is
indeterminate, with no retry; the evidence artifact records that result. Closing
HTTP does not prove runner cancellation.

## Acceptance and compatibility

Implementation follows strict RED → GREEN → REFACTOR. RED gates cover, at
minimum:

- the unchanged two-entry synthetic registry, immutable non-production status,
  production-catalog rejection, caller input/model/option/endpoint injection,
  fixed request bytes and the existing socketless worker;
- the forward-only evidence order `scenario_evidence_sealed_v1 ->
  ScenarioEvidence(preterminal) ->
  final_clean/pending (same hash becomes terminal_bound_v1) ->
  proven-recovery/terminal-owner ->
  evidence_envelope_sealed_v1 -> private artifact`; any envelope hash in
  `final_clean`, any envelope built before all three terminal projections, any
  earlier projection hashing the envelope, a backward envelope edge or failure
  of the whole-DAG topological check; every unequal-boot state before envelope
  sealing -- consumed prelease, opening/open without ScenarioEvidence, open
  with preterminal ScenarioEvidence, `final_clean` with
  pending/proven/failed recovery, and each failed terminal with
  pending/proven/failed recovery -- must win the unique-key CAS with exact
  `EvidenceEligibilityAbandonmentV1`; wrong `provider_evidence_present`, any
  newly created evidence/envelope/artifact, rewriting a historical
  ScenarioEvidence/final terminal/recovery/owner, or abandoning/rewriting an
  already sealed envelope; crash after cleanup or envelope sealing but before
  artifact publication, retry with original main memory/scratch/staged bytes
  absent, deterministic payload re-render byte/hash/size drift, a staged
  artifact path, non-Store source input, or non-atomic payload/projection
  publication; envelope/artifact publication from `preterminal`, a substituted
  `terminal_bound_v1` hash, a terminal-bound hash not byte-equal to the sourced
  `final_clean.scenario_evidence_hash`, or any mutation/reseal while changing
  the source qualifier;
- the construction order `static custody policy -> authorization -> attempt and
  lease nonce -> independent lease_id -> final operation recipes ->
  OperationLease -> opening -> capability registration -> credential-source
  pending -> O_CREAT_EXCL materialization/fsync -> exact credential-file
  observation seal -> credential-source ready ->
  post-capability load recipe -> LoadUnit`; authorization/custody policy containing an
  operation-local unit/subgroup/recipe, lease ID hashing any recipe/lease,
  prelease/capability/static policy hashing pending/ready source, actual inode,
  ciphertext hash or post-capability recipe, load recipe in OperationLease,
  recipe derivation before its preceding registration or any reverse edge;
  missing/wrong `worldforge_ollama_evidence_operation_lease_v1` format, an
  aggregate `worldforge_ollama_evidence_custody_handoff_v1` alias, Offer and
  Acceptance format substitution, any `broker_handoff_hash` field/alias in
  `open`, or any unknown RecoveryProjection field; exact 86-row vocabulary
  census, uniqueness/order/resolution, and mandatory presence of
  `worldforge_ollama_broker_ready_v1`,
  `worldforge_ollama_handoff_key_acceptance_v1`,
  `worldforge_ollama_candidate_configuration_payload_v1`,
  `worldforge_ollama_broker_result_payload_v1`,
  `worldforge_ollama_launcher_procfs_mount_identity_v1` and
  `worldforge_ollama_launcher_proc_fd_directory_identity_v1`, plus exact
  registration of `worldforge_ollama_deadline_credential_file_observation_v1`;
- exact 147/150-byte release-gate/lease-ID preimages and the published
  `508d3c...b4d4de`/`d5c634...2c344` golden digests, including literal domains,
  raw32 operands, `u64be(1)`, `bool8(false)`, every NUL and the one terminal
  NUL; raw-nonce versus nonce-hash or hex-text substitution;
- `ScenarioPlan.plan_maximum_bytes` missing, non-`pos53`, not exactly 524288,
  caller-relaxed or smaller than the canonical document; canonical scenario
  bytes above 524288 accepted for authorization;
- every `protocol_text` success-predicate cross product: non-HTTP/1.1/200,
  interim/duplicate/conflicting headers, non-single-JSON framing,
  chunking/compression, duplicate/malformed/trailing JSON, present `error`,
  nontrue `done`, wrong/extra semantic output, partial/extra/lost byte, timeout,
  reset or unclean close paired with `success_observed_v1`; and treating that
  one success predicate as evidence for any unexercised protocol branch;
- authorization/controller/owner forgery, copy, subclass, `object.__new__`,
  replay, expiry and drift; a proven-live-owner duplicate attempting recovery;
  recovery without kernel death/completed revocation/authenticated boot
  transition; non-atomic epoch bump and
  gate fence; owner-loss/revocation cutoff omission, boundary overlap or
  non-conservative interval; a crashed recovery owner acting again; recovery
  takeover without the prior recovery-owner retained-pidfd/`/proc` death proof
  or completed revocation; an old execution/recovery-epoch manager/release/
  config-disclosure/fork/listener/send effect; and unproven death/fence/effect
  order;
- exact `consumed_no_resources -> opening -> open -> terminal` ordering,
  immutable attempt terminals, recovery `pending -> proven|failed`, ACK-loss at
  every state, rejection of any separately ordered recovery-proven or
  owner-terminal write, the one atomic acyclic proven/terminal publication,
  owner/generation/recovery lock-release CAS, stale unlock, and content-free
  StudioStore schema/CAS isolation;
- every `StudioTransitionEventPayloadV1` key, closed event kind, exact
  attempt/transaction/Store revision, `none_v1` sentinel, ordered source/target
  set and cause; missing, extra, reordered, caller-invented or target-derived
  sources; every exact `StudioTransitionTargetBodyV1` key/bound, wrong
  source/target Store revision, target-body preimage, prior-event
  chain, transaction/event formula; missing/reordered OwnerCutoff/RecoveryFence/
  owner joint targets, same-transaction cutoff/fence used as recovery cause,
  underlying death/revocation/BootTransition proof substitution, or a
  result-derived Store revision; partial joint target or ACK retry that creates
  a second event/effect; adding event fields to a schema that does not declare
  them, filling authentication from an event, computing a target HMAC before
  its declared event/content references resolve, classifying ScenarioEvidence
  or EvidenceEnvelope `event_payload_hash` as an ordinary document reference
  instead of the exact domain-separated Studio event-payload hash, deriving
  either schema's `event_id` without the global event-ID formula, any
  self/forward sibling edge,
  sibling complete hash in a body, omitted/extra topological-table edge,
  same-event complete hash in any body/event preimage, or failure of the
  mechanical whole-table acyclicity check; every ordered key/type/bound/null/
  enum/event/auth/body/independent/sibling rule for launch lock, capability
  registration, manager-effect result, handoff chain and private artifact;
  either removed `manager_journal_v1`/`artifact_projection_v1` tag; consume
  without the prior unlocked lock or all three ordered targets; and Acceptance
  without its same-event chain target or with the wrong prior-chain source;
- every state-conditioned `(event_kind, ordered source states, ordered target
  states, cause type)` tuple and rejection of every unlisted cross-product or
  singleton substitute; `not_created -> static_action_loaded_inactive` without
  `deadline_action_load_transition_v1` consuming the exact ordered accepted
  LoadUnit/RefUnit results, ready credential source and post-capability load
  recipe; source ready without pending, without the uniquely committed exact
  `credential_file_observation_v1` cause, with an unknown/substituted format,
  hash, revision, identity or loss count, or pending after any create syscall;
  credential-file observation before fsync/close/zeroization, from a stale
  attempt/owner/pending source, or outside its named one-target event;
  `inert_unarmed -> inert_armed` without the ordered current
  `attempt:opening`, exact `owner:owned`, release and lifecycle sources, or
  acceptance after a terminal/non-opening attempt, recovering/terminal/stale
  owner, fired/recovery-fenced release, lifecycle drift or competing CAS;
  credential cleanup outside its single event, arm without its timer result; deadline fire/pending,
  recovery fencing/rebinding, terminal attempt/pending recovery, or pending
  lifecycle finalization outside their one named joint/bounded event; all
  R0--R12 source/target/cleanup paths, including immutable fired,
  recovery-fenced and invoked-terminal sources, R10--R12 lifecycle-only rebind,
  the sole same-boot old-epoch pending-finalization exception, and the exact
  one-target reboot-abandonment path for old-boot R6/R7; a generic reboot
  recovery-owner terminal row accepting R6/R7 without the exact
  DeadlineActionRebootAbandonment source; any valid pair with no
  cleanup path or a terminal pair rewritten as a target;
- exact ordered keys, types, bounds, nulls, enums and reference classification
  for InstallationObservation, ModelLock, ControllerPlan, ScenarioPlan,
  SystemdPolicy, OperationLeasePolicy, systemd-unit/native-process/candidate-
  subgroup recipes, CandidateRecipePolicy/final recipe, all
  three facet artifacts, NativeWireParserPolicy,
  NativeWireParserObservation, HttpWireBufferObservation,
  PrivateEvidenceArtifactPayload, EvidenceEligibilityAbandonment,
  DeadlineCredentialSource, DeadlineCredentialFileObservation,
  DeadlineActionLoadRecipe,
  DeadlineCredentialCleanupProof, DeadlineActionRebootAbandonment,
  ScenarioEvidence and EvidenceEnvelope; missing
  competing binary/layer/limitation, marketing identity promotion, raw/content
  hash confusion, facet substitution, unexercised branch, nonempty scenario
  failure, envelope-to-artifact/runtime cycle, unknown key or canonical size
  overflow; byte-for-byte reproduction of both 694/892-byte golden vectors and
  their exact SHA-256 values before any construction authority;
- canonical document hashing versus domain-ID, raw nonce/key-hash and HMAC
  domains; exact independently prederived authorization/recovery IDs and nonce
  hashes, caller-selected or consumer-derived IDs, wrong scalar encoding,
  null/zero/body/event/cross-chain/non-immediate substitution for any of the
  five exact prior complete-hash chains plus the launch-lock prior chain;
  independent release-gate nonce/ID,
  lease-to-gate one-way binding,
  exact domain-separated RecoveryFence, DeadlineTombstoneKey, Studio event and
  descriptor-198 record hashes,
  consumer-hash/cycle injection, prior-fence or independent-tombstone-nonce
  substitution; same-boot recovery with a boot-transition proof, reboot recovery
  with a cutoff/death/revocation proof, both proof families populated, or a
  fence document that hashes one of its consumers; deterministic lease/unit
  mutation; the exact capability/action-invocation ASCII domains, raw32/u64be
  ordering, every NUL including the terminal NUL, nonce-hash source, preimage
  lengths and both published golden SHA-256 vectors; and
  no manager effect before `opening` plus durable key/gate registration;
- the bracketed `CLOCK_BOOTTIME`/`CLOCK_MONOTONIC`/D-Bus observation sequence,
  signed negative lower offsets, exact nanosecond/microsecond guard inequality,
  offset conversion arithmetic, stale pre-suspend offset reuse, conversion
  tolerance/uncertainty/read-latency overflow, mandatory `WakeSystem=true`,
  exact `OnBoot`/`AccuracyUSec`/`RandomizedDelayUSec`/`RemainAfterElapse`, awake
  and suspend/resume proof, conservative enforcement latency, boot-ID change,
  and rejection of RuntimeMax or broker checks as primary deadline authority;
- durable keys, inert `Type=exec` operation, authenticated static action install,
  byte-for-byte 30-entry outer-service and 10-entry deadline-timer `a(sv)`
  arrays with exact order/name/variant/value and empty auxiliary arrays; any
  default/duplicate/unknown property, transient `Unit`, old timer basename,
  static unit-file bytes presented as transient properties, or property/
  `limits_hash` drift; local systemd 255's absent
  `StandardInputFileDescriptor:h` input contract or its
  `StandardInputFileDescriptorName:s` observation substituted as PASS rather
  than the explicit execution-unavailable conformance blocker;
  inactive instance `LoadUnit`, immediate same-connection `RefUnit(s)->()`
  only after exact credential pending/create/ready/load-recipe order; create
  before durable pending, parent/path/mode/owner/decryption-policy drift,
  missing `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, any truncate/rename/alternate
  path, mode other than `0400`, short write, missing file/parent fsync, ready
  before fsync/writer close, wrong ready dev/inode/stat/size/SHA/revision, or
  crash at pre-registration, pre-create, post-create/pre-ready and post-ready
  boundaries without its exact recovery branch; immediate same-connection
  `RefUnit(s)->()` before attestation/CAS, timer-primary `StartTransientUnit` with an exact
  empty auxiliary array, armed proof and release in that order; a missing,
  mutable or wrong-hash template/helper, separately transient/action-primary
  creation, wrong `LoadUnit` object, action start during load, nonempty auxiliary
  array, exact transaction replay/partial-object rejection, exact non-activating timer
  `Requisite`/`After` retention, rejection of `Wants`/activating edges, main
  early/missing/ambiguous Ref reply, early/retention-releasing Unref, static
  hash/property mutation while referenced, D-Bus death at every load/ref/CAS/
  timer boundary, exact `armed_not_invoked` versus `not_created`/historical
  loaded-state reconciliation, and unit-GC retention after connection ref loss;
  pre-timer main loss retained through failed `CollectMode=inactive` operation or live pidfd,
  plus activation/active deadline kills;
- all deadline-action lifecycle null/presence invariants, forged/wrong-direction
  or expired action Store capability, credential-role substitution, wrong
  executable/argv/unit/cgroup/action/PID1 invocation/owner epoch/gate revision,
  capability replay, arbitrary Store read/write/path/SQL attempt,
  tombstone-before-kill, action fire at every inert/check/release boundary,
  atomic `fire_committed_pending_terminal`, ACK loss after fire, missing/exceeded
  finalization deadline, forbidden old-epoch writes, and recovery finalization
  before/at/after that deadline on the same boot; boot transition while pending,
  any comparison/wait/conversion of the old-boot finalization deadline, an
  unequal-boot `deadline_action_terminal_v1`, reconstructed action/PID1 result,
  mutation of the old lifecycle, or missing/forged/wrong-cleanup/provider-bearing
  `OllamaDeadlineActionRebootAbandonmentV1`;
- forged, stale, expired, replayed, wrong-direction or chain-drifted
  `ReleaseGateSnapshot` or `ReleaseGateSnapshotAcceptance`, broker Store access,
  preissued bootstrap batches, Acceptance used before its exact record event,
  timing used before `operation_effect_timing_seal_v1`, wrong/missing sequence-0
  `none_v1` previous refs, or sequence>0 previous Acceptance/timing source
  substitution; acceptance/timing mismatch, predecessor-timing drift or
  violated issued/accepted/enter/return and cross-effect inequalities;
  every configuration, fork/exec, listener and send effect classified usable
  without a fresh sequential matching snapshot/Acceptance and same-clock effect
  timing strictly before deadline, tombstone, recovery fence and owner-cutoff
  lower bound; partial send, post-boundary or unprovable ordering must produce
  `deadline_race_indeterminate` and no evidence;
- missing, substituted, replayed, cross-epoch or oversized
  CandidateConfiguration Offer/Acceptance, operation result, terminal or ACK;
  wrong control sequence/prior-message chain, recipe/snapshot-Acceptance/effect
  observation-to-result-to-timing binding, wrong result-class/primary-observation
  type or outcome, observation/result/timing hash cycle,
  mutable/recopied configuration, premature broker launch, an
  open-ended result payload, provider content in a result/terminal, and broker
  closure without the exact Acceptance/ACK;
- unsupported/wrong/missing `StandardInput=fd` or
  `StandardInputFileDescriptor` D-Bus property/type/attached FD, nonempty
  operation auxiliary array, wrong fd0 socket/type/identity/peer, missing
  `SO_PASSCRED`, failed fd0-to-198 `dup3`, surplus fd0/descriptor, `Type=notify`
  or `sd_notify` fallback, missing/late/forged/replayed/oversized BrokerReady,
  Ready timeout/ACK loss, wrong ready-key credential/HMAC/zeroization, and
  candidate authority before valid Ready; HMAC handoff-key delivery before
  broker proof; wrong key/domain/serializer or
  code-2 key-Acceptance discriminator/version/principals/domain/canonical HMAC,
  seed code/sequence/record/payload/key identity, duplicate lookup or replay;
- wrong/missing/reordered systemd `User=ollama`, `Group=ollama`, empty
  `SupplementaryGroups`, `DynamicUser=false`, `NoNewPrivileges=true`, zero
  AmbientCapabilities/CapabilityBoundingSet, `DevicePolicy=closed` or empty
  DeviceAllow property/type; portable hardcoding or mutation of the
  installation-observed UID/GID; missing/malformed broker, child, service or
  runner `CredentialSnapshotV1`; unequal Uid/Gid quads, a distinct
  supplementary group, nonzero CapInh/CapPrm/CapEff/CapBnd/CapAmb,
  `NoNewPrivs!=1`, wrong status PID/start or credential-policy drift; any
  credential-changing syscall in the clone-to-exec census or post-exec
  credential drift, with retained-domain cleanup at every fork/handoff boundary;
  wrong Offer/Acceptance chain; receiver FD numbers in an Offer; altered reconciliation,
  reordered roles; any descriptor-198 unknown/wrong-direction discriminator,
  payload limit/header/hash/sequence/chain drift, unframed byte, missing or
  duplicate `SCM_CREDENTIALS`, `SCM_RIGHTS` outside the exact code-3 one-FD
  transfer, or returned flag other than exact `MSG_EOR`; `MSG_TRUNC`/
  `MSG_CTRUNC`, missing/extra/duplicate cmsgs or FDs, wrong peer/census/slot/
  flags, missing/late/reset `SO_PASSCRED`, surplus/replay, ACK loss and owner
  swap;
- a key page lacking `MADV_DONTFORK|MADV_DONTDUMP`, Python/raw key copy, missing
  native zeroization, mutable fork recipe, unavailable/drifted `clone3` or
  launcher/library authority, a launcher or static profile/policy that hashes
  the final operation recipe, final-recipe/profile/policy substitution,
  sibling TID or task-census mutation before key/configuration/launch, thread
  creation/callback surface, concurrent candidate launch, unblocked catchable
  signal, audit/Python/atfork
  callback in the fork window, child acquisition of a key, descriptor 198 or a
  control/configuration writer, surplus child FD/map, wrong 0/1/2 role, barrier
  bypass, incomplete census, exec/cgroup/pidfd drift; launcher pre-exec
  `/proc/self/fd` access missing the exact read-only flags/mount/directory
  identity, using any syscall/path/network/device I/O outside the frozen list,
  a temporary census dirfd surviving exec, candidate AccessPolicy starting
  before successful exec or containing that launcher-only dirfd/path, or the
  boundary observation missing on success/present on failure; and treating
  `FD_CLOEXEC` as the inheritance proof;
- system-PID1-only selection, manager reload/evidence loss, stale custody proof,
  provider-run self-proof, semantic/main-loss/custody sentinels, retained
  terminal and action-lifecycle CAS while loaded, ordered timer/action closure,
  then cleanup fixed-point CAS before lock release, logical controller
  construction with no controller process/pidfd/separate channel, and crash of
  each actual authority;
- exact `no_candidate_resources_v1` zero-effect journal; authenticated first
  `StartTransientUnit` rejection reply journaled immediately plus two stable
  exhaustive censuses in `manager_transaction_rejected_no_resources_v1`; lost
  or ambiguous D-Bus reply classified `manager_transaction_unknown` with no
  serial re-read/no-resource proof; rejection-mode misuse after any allocation;
  `same_boot_retained_systemd_domain_v1` after broker death or an incomplete
  service/runner pidfd handoff at every spawn, Offer and Acceptance boundary,
  with exact retained unit/cgroup/terminal fixed point and no missing-pidfd
  reconstruction; live-main versus both exact offline retention sources with no
  pidfd reconstruction;
  immutable `failed_cleanup_pending`; every post-capability normal/failure/
  recovery/reboot path missing `DeadlineCredentialCleanupProofV1`, null proof
  despite capability registration, wrong source generation/boot/branch,
  skipped/reordered cleanup generation, wrong prior-proof hash, a second proof
  in one owner epoch or a later recovery proof without the exact fenced prior,
  plaintext/key/ciphertext working copy or FD not closed and zeroized,
  pending-file adoption without capability authentication, ready-file identity
  drift, unlink by raw path or nonmatching inode, missing parent-dirfd/fsync/
  post-unlink ENOENT/unchanged-parent proof, substitution/race/loss accepted,
  or any leftover credential file; and raw-PID/name/inode-scan rejection;
- `reboot_abort_no_evidence_v1` with equal/forged boot IDs, stale owner/fence,
  no-resource cleanup after a lease exists, `opening` with unequal boot and a
  null reboot-abort observation, pre-lease zero-allocation reboot misclassified
  as provider evidence or anything other than failed-clean/clean-no-launch,
  old-terminal or old-pidfd reconstruction, missing deterministic-unit/job,
  listener/IPC or device re-audit, reused resource, lost/inaccessible census,
  unjournaled/unscrubbed scratch or secret sink, any newly created provider
  evidence/receipt or a `provider_evidence_present` value unequal to exact
  preexisting ScenarioEvidence-hash presence,
  an OwnerCutoff on reboot, a reboot R6/R7 path without its immutable old
  pending lifecycle and current-boot abandonment projection, abandonment
  before the exact reboot cleanup proof, old boottime deadline comparison, or
  action-terminal reconstruction,
  `final_clean`/observed/PASS publication, and unlock before its exact cleanup
  proof plus joint recovery/owner terminal CAS; `final_clean|failed_clean` with
  pending recovery and reboot owner lacking the one narrow post-terminal
  cleanup transition, using that transition without exact BootTransition/
  `reboot_abort_v1` fence/eligibility-abandonment/current-boot absence equality,
  mutating the terminal attempt or ScenarioEvidence, populating abandonment on
  a mutable preterminal cleanup proof, or reaching envelope/artifact/provider
  publication after the narrow transition;
- exact CPU-only/no-device closure and rejection of
  `accelerator_observed_v1` as a V1 profile/mode/PASS; nonempty `DeviceAllow`,
  a candidate-visible character/block device other than the exact inherited
  read-only `/dev/null` fd 0, mutation/substitution of its stat/rdev/mode/flags
  or candidate opening of `/dev/null`; treating that declared stdin role as an
  accelerator permission or requiring an impossible zero-all-device-FD proof;
  candidate accelerator device open/mmap/ioctl, accelerator library/runtime/backend
  selection or nonzero attributable context/work; separation of candidate zero
  rights from observer read-only census rights, observer device-control attempt,
  unsupported/inaccessible/lost observer rejection, fresh scratch and limits,
  causal peer attribution/rebind, runner transitions, DNS/proxy/redirect/retry
  exclusion, pre-send cleanup versus post-send indeterminacy, capture loss,
  unexpected sockets/IPC/writes; missing, extra, reordered or mutated
  `AmbientSinkCatalogV1` entries, catalog overflow/loss/raw-content publication,
  or treating an outside-catalog host sink as an enumerable absence gate; raw
  provider content in any World Forge public or durable Store/receipt/EventLog,
  any controller HTTP wire path/file/memfd/shared-memory/scratch/log write,
  file-backed mapping, missing/wrong `MAP_PRIVATE|MAP_ANONYMOUS` or
  `MADV_DONTDUMP|MADV_DONTFORK`, page-round overflow, unavailable/insufficient
  `RLIMIT_MEMLOCK`, partial/failed `mlock`, locked-page or full-process mapping
  census loss/drift, capacity/total overflow, raw replay retention, a parser
  allocator call, raw-byte/string/header copy or ordinary-heap materialization,
  third working mapping/buffer, parser syscall/fd/thread drift, nonzero parser
  loss/count, missing native-parser identity/proof, or parser result not bound
  to the same two mappings; a wire byte in ScenarioEvidence/artifact, missing
  content-free buffer observation, failed/wrong-order `explicit_bzero`,
  zero-range proof, `munlock`, `MADV_DONTNEED` or unmap, cleanup without the
  required zeroization hash, absolute no-persistence/no-host-capture claim,
  missing exact residual hibernation/crash/external-capture risks, or treating
  failed locking as a no-swap result; ambient host capture treated as impossible
  or undoable, privacy, observed
  usage and duplicate zero effects; and every exact ordered
  `OllamaEvidenceLimitsV1` key/value/hash, cross-layer scenario/access/recipe/
  unit/configuration/result binding, rlimit-versus-FD-census effective minimum,
  `TasksMax=512` versus the independent 31/30/29 process-identity censuses,
  counting a thread as an accepted process identity, using 31 as the systemd
  task ceiling, omitting `kernel_task_ceiling` or caller relaxation of either
  layer,
  response-wire-versus-total-capture bounds, scratch-quota-versus-scenario
  acceptance minimum, overflow and caller relaxation; and every exact ordered
  `OllamaEvidenceAccessPolicyV1` key, nested entry schema, bound/count/enum,
  candidate subject, input/end-point/IPC/writable/sink/device list, process/FD/
  network right, descriptor-198 code order, limit/timeout, capture/privacy/
  cleanup/failure literal, unknown-key rejection and hash drift.

An explicitly authorized native evidence run may exercise only its exact
declared scenario, and only after the separately sacrificial custody proof,
two-clock timer/action semantics, persistent unit-GC retention, execution-owner
fencing, narrow deadline-action Store port/capability, release snapshots,
retained terminal path, HMAC handoff, native fork-safe launcher/key vault and
exact device observer have all been live-proven and hash-bound. It must truthfully record
whether that scenario's branch ran, prove peer and service/runner transitions,
inventory the exact selected CPU backend plus the no-accelerator-device census
and model observations, capture only the declared protocol/control facet, close
the finite egress/log window with zero loss, and prove cleanup. An unexercised
or incomplete branch remains missing evidence; a later controller revision
requires a new exact authorization. Only an internally complete envelope for
its declared scenario whose immutable attempt is `final_clean` and recovery is
`proven` may carry the non-executable `observed_nonproduction` label; no
synthetic fallback is allowed. This ADR records **no passing live gate** and no
current execution authority. Even such evidence leaves
`production_eligible: false` and cannot enable a turn; executable work requires
the separate implementation ADR and may support only facets actually observed.
Every feature, error/status/framing branch, cancellation timing and lifecycle
transition not exercised by that exact scenario remains `unavailable`.

Public Harness v1 schemas, EventLog v3, `src/isoworld`, the socketless worker,
and both synthetic runtime identities remain unchanged. Python 3.11, x86_64,
Windows, macOS, hosted execution, deterministic replay, authenticated upstream
model identity, proof of the exact loaded blob, zero egress, zero telemetry,
billing and production readiness remain `UNTESTED` or `PENDING`, never PASS.
