# Architecture

The canonical design is `docs/MULTI_GENRE_ARCHITECTURE.md`; current proof levels
are `docs/SUPPORT_MATRIX.md`. World Forge has two additive lanes. Authoring
validity is not runtime executability, and neither lane may silently project
into the other.

## Generic creation lane

```text
creation project + independent profile facets
        -> typed source modules
        -> integral validation + phase-report v3 P00-P14
        -> immutable gamepack + bounded analysis + mechanic ledger
        -> gamepack asset subject -> D1 planning -> D2 production/QA -> D3 seal
        -> code-owned adapter registry/snapshot + compatibility evidence
        -> runtime bundle -> materialization bundle -> external standalone game
        -> headless/save/replay/package -> native evidence per declared platform
```

Every arrow binds exact format/version/ID/hash inputs, output identity, stable
failure state, and evidence. A generic creation library is neutral authoring,
not an executable game. A compiled gamepack is not a sealed assetpack; sealing
is not adapter verification; headless is not native; local is not hosted.

The generic runtime is bounded to the neutral `gamepack_runtime` state machine
and the implemented puzzle/text raylib 2D adapters. Their local recording and
headless tests are not native Linux/Windows proof. Complete generic 3D and mixed
adapters are not implemented.

## Legacy RPG lane

```text
Forge repository                       world-authoring repository
(skills, templates, tools) --operates--> source + .worldforge + assets
                                                   |
                                      validate, compile, approve
                                                   |
                                                   v
                                      immutable runtime bundle
                                      (worldpack, renderpack,
                                       processed assets, licenses)
                                                   |
                                      verified external import
                                                   |
                                                   v
independent game repository <---------- copied, hash-locked data
(pyray/raylib code, UX, saves, packaging; no authoring control plane)
```

This retained specialization uses the published world project, worldpack,
renderpack/assetpack, composed bundle, `isoworld`, and pyray contracts. It is
not the generic authoring model and `src/isoworld` remains stdlib-only.

## Forge Studio application-service boundary

Forge Studio is an authoring-time control plane under `worldforge`; it is not a
runtime feature and never enters a worldpack, renderpack, assetpack, immutable
bundle, or generated game. The first service boundary is deliberately
provider-free:

```text
sandboxed React renderer
        |
        | fixed typed preload operations; validated top-frame IPC
        v
Electron main supervisor -- serves --> rwf-studio://app static artifacts
        |
        | bounded strict NDJSON request/response/error/event envelopes
        | over stdio; shell=false; fixed executable and arguments
        v
worldforge.studio application service
        |-- public schema validators
        |-- workspace boundary inspection
        |-- revision-guarded PNG/WAV preview leases
        |-- SQLite registry, events, and job state
        `-- approved, base-hashed source changesets
                |
                `-- world lifecycle lock + durable external apply journal
```

Electron main also owns a distinct Codex app-server boundary. It binds one
registered canonical world root as the child working directory, creates a
dedicated `CODEX_HOME`, and starts exactly Codex 0.144.6 with
`app-server --stdio --strict-config`. The generated config fixes approval to
`never`, sandboxing to read-only, network/web search off, empty shell
inheritance, and one Forge MCP server. That stdlib MCP child is bound by argv to
the Studio data directory and workspace ID and exposes only changeset stage,
get, and list. It uses a secondary store attachment that never migrates the
database or performs primary-service job or journal recovery.

Canonical project files remain the source of truth. The SQLite database, staged
content-addressed blobs, and apply journals live only under the explicit
`--data-dir`; they are never placed in the Forge, world, bundle, or game roots.
The database uses foreign keys, WAL, FULL synchronous writes, and a bounded busy
timeout. A service restart marks interrupted `running` jobs as `orphaned` and
records that transition as an event.

The service's read-only authoring boundary is manifest-authorized rather than a
general filesystem browser. `source.list` and `source.read` expose only the
manifest, world document, and collection documents named by the loaded source
manifest. Paths are portable, depth/count/byte bounded, collision checked, and
read through the same pinned no-link/no-hardlink boundary as changesets. The
reported hash, UTF-8 content, and strict JSON value derive from one stable byte
snapshot. `world.validate` and `world.analyze` construct the existing
`SourceProject` in memory and reuse the established release validator and
narrative analyzer; they never call report writers. `workspace.overview`
projects identity and lifecycle status without returning absolute roots.

A workspace requires the active Forge repository and one canonical v2 or v3 world
repository. Optional game and bundle roots must pass their existing standalone
boundary inspectors. Symlinked roots, repeated filesystem identities,
casefold/NFC aliases, and nested or overlapping responsibilities are rejected.

Studio changesets are not arbitrary filesystem patches. New version 2 records
permit creation, replacement, or deletion of standalone UTF-8 regular files
only beneath `source/`, with portable paths and existing parent directories.
Each operation retains exact base and proposed snapshots, when present, by
SHA-256 outside the repository. A canonical review hash commits to the ordered
path, operation, hashes, and byte sizes. Exact bounded text hunks and optional
strict-JSON Pointer changes are reconstructed only from those owned snapshots;
they never reopen the mutable workspace. Version 1 records remain readable and
actionable, but expose a typed unavailable review because their base bytes were
not retained.

Approval and apply are separate state transitions. Every v2 action must echo
the exact reviewed hash. Apply atomically claims the durable `applying` state
before publishing a journal or touching source files, which blocks rejection
and concurrent application. Apply rechecks roots, parents, link counts,
identities, hashes, sizes, and base state while holding the existing world
lifecycle lock. The public path
schema names the `rpg-world-forge-portable-source-path` format and carries the
NFC, traversal, reserved-name, trailing-dot/space, and UTF-8 component limit
policy consumed by the shared Python validator. POSIX mutations are relative to
a verified directory-descriptor chain; Windows holds no-delete handles for the
entire directory chain. Visible identities are rechecked through the durable
file and SQLite commit. Version 2 journal intent binds the changeset version,
review hash, and ordered operations; every reserved stage name is durable before
a stage is created. Startup validates that identity before recovery and releases
an orphaned `applying` claim only when no journal was published, the point before
which source mutation is impossible.
Same-directory exclusive link/unlink publication and the identity/hash journal
provide crash recovery and rollback. POSIX flushes file and directory metadata;
Windows uses write-through journal replacement plus `FlushFileBuffers` on the
affected directory handle. If either platform cannot expose its required
durability primitive, apply fails closed instead of claiming an equivalent
guarantee or overwriting an unowned path.

Managed v2 durable jobs execute only four closed, read-only operations:
`asset.receipt.validate`, `assetpack.verify`, `runtime.headless`, and
`runtime.replay`. The original broad v1 records remain valid for read, recovery,
and cancellation, but are never executable or retried. One FIFO scheduler owns
a secondary SQLite connection and atomically claims at most one eligible queued
v2 job. Each claimed job runs in a fixed child worker with bounded strict JSON
pipes, a sanitized environment, workspace-derived roots, stable standalone-file
proofs, a timeout, and process-tree termination.
Progress and cancellation intent are durable events. A service shutdown reaps
its active child before marking the job orphaned; restart recovery never retries
an orphan automatically. Public transitions cannot impersonate the executor.

The Electron renderer can list and cancel jobs and create them only through four
fixed named capabilities: receipt validation, assetpack verification, headless
runtime, and replay runtime. Electron main maps those capabilities to the four
managed operation literals, validates each correlated v2 reply and echoed input,
and never exposes arbitrary `job.create` or operation dispatch. Codex proposals
remain staged changesets and cannot approve or apply themselves. Provider/model
execution, Blender, Modly, Ollama, arbitrary commands, file watching, and M6
presentation work remain outside this boundary.

The renderer's Game cockpit is a defensive view over three of those named
capabilities: `assetpack.verify`, `runtime.headless`, and `runtime.replay`.
Forms start with blank portable workspace-relative paths; headless ticks are
integers from 0 through 1,000,000. Each request captures the selected workspace,
workspace generation, and a local request token, so a late reply cannot enter a
new workspace view. The immediate correlated queued record is merged before the
bounded job/event lists refresh. Projection admits only current-workspace v2
records with exact operation-specific inputs and results; legacy, malformed,
other-operation, and other-workspace rows are absent. Progress is a running-only
observation associated by workspace, job entity, and event identity. A running
job without such evidence is indeterminate, and terminal jobs do not invent a
final percentage. The main Game view renders controlled structured facts and
error copy rather than raw JSON, details, stderr, or roots. It verifies an
existing replay only and provides no recording, generated-game slot, launch,
bundle/package, native renderer, or M6 3D capability.

Asset previews are a separate three-method named boundary, not generic file
access. The renderer can provide only a workspace/revision/entry tuple to open,
then an opaque handle and bounded sequence to read or close. Python owns one
preview manager, immutable snapshot lifetime, quotas, and shutdown cleanup.
Electron main validates handle, authority, sequence, cumulative length, EOF,
and SHA correlations, decodes canonical base64 immediately, and removes the
encoded field before returning a fresh `Uint8Array` through preload. Only PNG
and WAV are authorized; no preview UI is part of this boundary change.

Development selects Python and Codex through explicit absolute
`WORLD_FORGE_STUDIO_DEV_PYTHON` and `WORLD_FORGE_STUDIO_DEV_CODEX` paths.
Deprecated `RWF_STUDIO_*` aliases are accepted only when they are not in
conflict. A package may select
them only through the closed runtime manifest and pinned protocol provenance in
Electron resources; it never searches `PATH`. Packages without both native
runtimes report the bridge unavailable. Renderer artifacts use the same registered custom
scheme in development and release, with no localhost or HMR server.

### Studio runtime distribution boundary

Technical provenance, acquisition, assembly, and distribution authorization are
separate layers. The checked-in x64 runtime-source contract pins exact Codex and
Python inputs, but it also reports `release_ready=false`, redistribution
`blocked`, and seven structured legal/provenance blockers. Real runtime assembly
checks that authorization before opening an archive or creating an output and
therefore fails closed today.

Acquisition caches, assembled resources, package trees, ZIPs, games, and
end-to-end artifacts must live outside the Forge repository. Synthetic archives
exercise bounded deterministic assembly and verification without creating
redistributable runtime material. Linux output construction uses
descriptor-relative no-follow operations; Windows uses retained
`NtCreateFile` root-directory handles and rejects reparse points. Hosts without
the required identity-preserving primitives fail closed.

The Electron package boundary is independently testable in `shell_only` mode.
It statically verifies hardened fuses, exact ASAR and resource inventories,
source-to-package correlations, and final retained identities without launching
Electron. A valid shell-only result proves that Python and Codex are absent,
retains every blocker, and remains `release_ready=false`; it is not a
self-contained Studio release. No runtime-download, signing, self-contained
artifact, or publication CI is authorized until the provenance, notices, SBOM,
source/relink materials, pruning decisions, redistribution authority, and
attestation evidence close together. [ADR-0021](decisions/0021-studio-runtime-distribution-boundary.md)
records this boundary.

AI is not a game subsystem. It does not decide dialogue, quests, routes, or
actions during play. It may propose authoring material, but that material must
be reviewed and compiled before it reaches the runtime.

## M6 runtime-composition contract boundary

M6 composes unchanged M5 artifacts before it implements or selects a runtime:

```text
worldpack v1-v5 ----+
renderpack v1 ------+--> hash-bound composition --> compatibility report
assetpack v1 -------+          |                          |
capability catalog -+          v                          v
presentation profile       declared/verified adapter   static checks
```

Six profiles define only the world planes: 2D, 2.5D, 3D, 2D over 2.5D, 2D over
3D, and 2.5D over 3D. UI and audio are orthogonal planes. The composition binds
each selected semantic slot to one plane, pack, asset, and representation.
Renderpack v1 remains unchanged; its selected bindings receive 2D/2.5D
classification from the outer composition. Assetpack representation must match
the sealed binding exactly.

The adapter document is a requirement declaration, not an implementation
locator. It contains no module, command, executable, provider, model, or MCP
endpoint. Only `verified` state can satisfy compatibility, and verification
still requires all pack, profile, platform, runtime API, capability, semantic
ownership, and world-identity checks. These contracts do not claim a native 3D
runtime, collision, animation, composed bundle, package, or M6 release.

[ADR-0016](decisions/0016-runtime-composition-contracts.md) records this seam.

### Immutable composed bundle

Once an exact static registry can satisfy a verified adapter declaration, the
Forge can seal the four M6 contracts, a freshly recomputed compatibility
report, the unchanged selected worldpack/renderpack/assetpack payloads, and
approved notices into `rpg-world-forge.composed_runtime_bundle` v1. The bundle
has an exact portable tree and file inventory, is published without
replacement, and is loaded only through private identity-owned snapshots.

The bundle stores declarations and compatibility evidence; it contains no
Python locator, command, provider, model, MCP endpoint, authoring receipt, or
workflow. Loading resolves an exact code-owned registry value but never invokes
it. Therefore a valid composed bundle is not evidence of native rendering,
physics, animation, playability, performance, packaging, or M6 release
readiness. [ADR-0017](decisions/0017-immutable-composed-runtime-bundle.md)
records the ownership and publication boundary.

### Registered legacy 2.5D adapter

`isoworld_raylib_2_5d@0.1.0` exposes the established isometric runtime through
the exact static adapter registry for Linux x86_64 and `profile_2_5d` only. Its
22 declared capabilities were derived from and verified against the checked-in
foundation worldpack's 19 required runtime features plus worldpack v1-v5,
renderpack v1, and 2.5D world presentation. The declaration is not bound to
that world's hash: another worldpack may pass when its requirements are a
subset of those capabilities and its renderpack has the same world identity.
The renderer proves 2.5D through isometric projection, authored elevation, and
stable depth sorting; its use of `Camera2D` does not establish a separate 2D
profile.

Registry lookup returns a frozen opaque value and imports no pyray.
`preflight()` checks one already-loaded worldpack/renderpack pair, verifies
that every required runtime feature is covered, enforces matching world
identity, five-asset/three-binding limits, and at most 1 MiB of hash-verified
resource bytes, then `create_app()` delegates to the unchanged `GameApp`. The
1024 draw-call and 1000 ms values are smoke ceilings, not representative
performance evidence. The schema-required triangle value is a non-3D floor and
proves no mesh behavior.

The declaration omits 2D, mixed, 3D, assetpack, collision, UI, audio,
packaging, Windows, and performance readiness. Ubuntu x86_64 CI exercises the
exact adapter seam through the existing hidden-window smoke; local aarch64
execution is not evidence for that platform. [ADR-0019](decisions/0019-legacy-pyray-2-5d-adapter.md)
records these limits.

### Bounded pyray GLB proof

The bounded 3D evidence adapter is deliberately narrower than every committed
3D presentation profile. `pyray_3d_v1` accepts one exact snapshot-relative
skinned GLB, one `actor:<id>` binding, one named animation, one uniform scale,
and one presentation layer. Pure functions map the immutable `RenderState`
grid, select animation frames from `RenderState.tick`, transform finite local
bounds, and return an admitted picked cell. They never dispatch an action,
reduce `WorldState`, or treat model bounds as collision or navigation data.

The native session resolves only a portable payload path through the owner of a
private bundle snapshot. It verifies the declared size, SHA-256, triangle and
loaded-byte budgets before opening a hidden window, then uses path-only
`load_model`, the CFFI animation-count pointer, exactly one animation name and
positive compatible skeleton/keyframes. The pointer is the binding's audited
signed `int *`, and the synthetic one-second animation's two source samples
become exactly 61 binding keyframes at raylib's 60 Hz glTF sampling rate.
Cleanup unloads the complete animation array before the model and closes the
window last. The resolver remains owned until cleanup succeeds.

The declaration proves only `animation_gltf`, only on Linux x86_64, and omits
assetpack consumption, 3D/mixed world presentation, collision, packaging, UI,
audio, and performance claims. All current 3D/mixed profiles require
`collision_gltf`, so they remain incompatible. The pinned Python distribution
is exactly `raylib==6.0.1.0`; ABI inspection records that its bundled constants
identify the header as `6.1-dev` and RLGL as `6.0` rather than relabeling that
observation as stable raylib 6.0.

Ubuntu x86_64 CI must execute the synthetic skinned-GLB hidden-window smoke.
Windows CI records distribution/header/RLGL/function-surface evidence only and
explicitly does not claim native 3D verification. This slice is not a playable
3D game, a standalone package, a composed-bundle consumer, or M6 readiness.
[ADR-0018](decisions/0018-bounded-pyray-3d-proof.md) records these limits.

## State flow

The runtime uses a small reactive-style flow:

```text
Input -> GameAction -> reducer(WorldState) -> new WorldState
                                             |
                                             v
                                  immutable RenderState
                                             |
                                             v
                                          Renderer
```

- `WorldState` is the simulation source of truth.
- The reducer applies pure, reproducible actions.
- `RenderState` is a frozen snapshot; rendering cannot touch `WorldState`.
- `FixedStep` keeps simulation stable across frame rates.
- Future systems react to domain events instead of calling one another through
  circular dependencies.

Navigation, clock advancement, schedules, needs, goals, construction,
production, interactions, abilities, narrative events, delayed consequences,
quests, dialogues, scenes, and reservations stay inside reproducible state
transitions. Persistence serializes only `WorldState`; rendering still consumes
a separate frozen snapshot.

```text
tick -> clock -> needs/completions/consequences -> goals -> schedules -> routes
input -> move/navigate/interact/use_ability -> reducer -> new WorldState
input -> build/produce/transfer -> reducer -> domain events -> new WorldState
event -> bounded quest transitions -> eligible scene -> new WorldState
input -> dialogue choice/dismiss scene -> reducer -> new WorldState
save/replay -> world ID + content hash + state/action digest
```

## Layers

1. `core`: application, input-to-action mapping, and fixed step.
2. `world`: state, deterministic rules, navigation, and simulation.
3. `content`: loading of already-compiled worldpacks.
4. `render`: isometric projection, snapshots, and raylib drawing.
5. `ui`: presentation in the worldpack's language; no domain rules.
6. `worldforge`: authoring/build tools that runtime never imports.

The worldpack owns simulation and narrative semantics. Version 4 added typed
resource, need, goal, stockpile, construction, production, and consequence
collections. Version 5 adds explicit runtime API/features, BCP47 locales, and
typed personal campaigns while retaining v1-v4 loading compatibility. The renderpack owns the
replaceable mapping from semantic slots such as `actor:hero` or
`tile_type:ground` or `construction:workshop` to processed textures,
deterministic clipsets, fonts,
shaders, SFX, and music. The asset-production manifest is never loaded by the
game because it may contain recipes, model identifiers, extension workflows,
references, and licensing evidence.

Processing recipes remain format v1. The pure recipe validator resolves only
the explicitly supplied recipe beneath an authoritative asset root, verifies
its hash-bound inputs and closed operation contract, and performs no media
decode, processing, or writes. New processing receipts use format v2 and bind
that exact recipe path, raw SHA-256, canonical content hash, operation, input
IDs/files/hashes, and output filename/role/media lineage. Manifest validation
passes its own asset root explicitly. Receipt v1 remains readable as an
identity-only legacy record; it never gains inferred recipe authorization.

## Historical Slice 1A planning vocabulary

This section records the historical Slice 1A architectural plan. Slice 1B.1
additively supersedes its Harness-only statement with two public immutable
lineage schemas; it does not implement any execution surface. All remaining
items below remain planning vocabulary, not an implemented Studio feature,
runtime claim, provider integration, or generated-game requirement. It
preserves all published contracts and the existing provider-free Studio
boundaries.

The future World Forge-owned, provider-neutral Agent Harness is planned to add
an append-only event log and replay, isolated killable worker lifecycle,
execution receipts, and approved memory projections. Slice 1B.1 now publishes
only the closed `AgentWorkerActivation` and `AgentCapabilityGrant` lineage
contracts. Slice 1B.2 adds the closed `AgentEvent` and
`AgentExecutionReceipt` contracts. Slice 1B.3 adds the final closed
`AgentMemoryProjection` contract. Their validation does not prove execution,
isolation, authority, replay, evidence quality, or memory truth. Studio alone retains
project, canon, asset, and release authority. DeepSeek Harness is reference
material, never a dependency or fork. `codebase-memory-mcp` is an optional,
read-only development benchmark only: it is not a source authority, product
dependency, or runtime input. See
[ADR-0026](decisions/0026-world-forge-agent-harness.md).

The future Virtual Studio vocabulary is `DepartmentDefinition`,
`WorkerProfile`, `StudioRoster`, `WorkOrder`, `TaskLease`, `Handoff`,
`DefectRecord`, `ConsultantEngagement`, `CompetencyAttestation`,
`UserDecision`, `TeamSession`, `ParticipantBinding`, and `DeliberationReport`.
V1 has one human director; stable profiles receive fresh task context; owners
repair defects and independent QA verifies them. Consultants require user
approval. Team Mode requires exactly three distinct model lineages; if they are
unavailable, the Studio shows a visible degraded mode and does not claim
consensus.
See [ADR-0027](decisions/0027-virtual-studio-governance.md).

The implemented Forge-independent `gamepack_runtime` kernel is the neutral
runtime boundary. Slice 5 plans an additive formal SDK/ABI role and evolution,
not its future existence. Each Slice 5 materialized external game will own
editable `src/engine/` and `src/game/`, an exact `engine.lock.json`, and an
immutable `src/isoworld/` snapshot where the legacy snapshot applies.
`EngineProfile`,
`EngineLine`, `EngineRelease`, `EnginePackage`, `EngineLock`,
`EngineCompatibilityReport`, `EngineMigrationPlan`, and
`EngineMigrationReceipt` name lineage, immutable releases, locking,
compatibility, and change evidence.
Only within editable `src/engine/` may declared `src/engine/adapters/` code
import pyray; immutable legacy `src/isoworld/` retains its published
compatibility imports. A development-only `GameControlPort` is excluded from
releases. The current scaffold remains unchanged until Slice 5. See
[ADR-0028](decisions/0028-project-owned-engine-lines.md).

The future Tool Center has exactly `Capabilities`, `Workflows`, and `Runs`.
Setup/Health is an auxiliary drawer, Node Catalog is within Workflows, and
Outputs/QA belongs to a run and Creation > Assets. It will use capability,
workflow, dependency, run, receipt, and output-candidate contracts; Modly and
ComfyUI remain provider-specific adapters. A logical schema-approved DAG does
not authorize arbitrary frontend code. Slice 1 provides no discovery,
installation, execution, or Tool Center UI. See
[ADR-0029](decisions/0029-tool-center-capability-workflow-run-model.md).

GitHub Actions are intentionally absent at baseline
`8334f2536ee03f541cbee7f729379139e70241df`. Applicable local verification and
independent fresh review govern future implementation. `hosted_evidence` stays
`PENDING` and native evidence stays `UNTESTED` without exact real evidence;
local results never become hosted or native passes. CI restoration is separate,
explicitly authorized, time-boxed work.

## Creative-process control plane

Every generated **world-authoring repository** contains `.worldforge/` and a
tailored `AGENTS.md`. GPT reads its status, works only on the active phase, and
submits a phase report with deliverables, decisions, blockers, and validation
evidence. `complete-phase` prevents phase skips or evidence-free completion.
Optional subagents claim non-overlapping paths; only the lead GPT integrates
canon.

The Forge repository is the only home for reusable `.agents/skills`. The game
repository has no `AGENTS.md`, `.agents/`, `.worldforge/`, source canon, prompts,
phase reports, or asset-production evidence. Forge-side agents may construct or
update a game through explicit external paths, but no agent control plane is
materialized into the game.

`worldforge audit-game <game-repo>` enforces this seam. It rejects known agent
and workflow paths, editable source roots, authoring-only JSON formats,
`worldforge`/Modly/AI imports, and corresponding Python project dependencies.
Game materialization, runtime/platform migrations, and bundle imports must pass
this command before handoff.

The generated game has two independent locks:

- `runtime.lock.json` inventories the complete vendored `src/isoworld` snapshot;
- `platform.lock.json` records the Python range, exact binding distribution and
  version, backend, native raylib API, and `pyray` import boundary.

The platform contract is enforced by a resolver-facing artifact:
`requirements.lock` lists the exact dependency/build graph consumed by CI and
must agree with both the platform lock and `pyproject.toml`.

Game-specific implementation lives under `src/game`. Agents never edit the
locked `src/isoworld` tree in place: reusable runtime changes are implemented
and tested here, then replace the whole snapshot through an optimistic-hash
Forge operation. Imported bundles are similarly replaced only by importing a
new stable SemVer release. Platform migration is a separate phase that updates
its lock, exact dependency, CI, notices, and native evidence together.

## Repository responsibility matrix

| Concern | Forge | World authoring | Runtime bundle | Game |
| --- | --- | --- | --- | --- |
| Agent skills and generic prompts | Owns | Uses externally | Never | Never |
| Canon and editable narrative source | Never | Owns | Compiled only | Never |
| Asset candidates and production evidence | Generic tools only | Owns | Never | Never |
| Worldpack, renderpack, processed assets | Builds/verifies | Releases | Owns immutable copies | Imports locked copies |
| Pyray/raylib application, UX, saves, packaging | Templates/reference | Never | Never | Owns |
| Runtime/platform locks and migrations | Builds and operates externally | Never | Declares requirements only | Owns locked copies/config |

## Non-negotiable contracts

- Runtime does not import `openai`, `anthropic`, `transformers`, `langchain`,
  `litellm`, `ollama`, `llama_cpp`, or equivalent packages.
- Assets and worldpacks are distributable without credentials.
- One seed and the same action sequence produce the same state.
- Saves and replays must match the exact compiled world content hash.
- No two actors may occupy or reserve the same destination cell in one tick.
- Construction footprints cannot overlap actors, terrain, or other structures.
- Stockpiles remain non-negative and cannot exceed declared capacity.
- Goal selection is stable by priority, hierarchy depth, and ID.
- Delayed consequences carry absolute due minutes and survive save/replay.
- Water is not walkable or arable.
- Rock and vegetation are not arable by default.
- Manual tile decisions take priority over generated decisions.
- Each world declares its visible language and localization policy.
- Release worldpacks contain no `TODO`, `TBD`, template braces, or broken refs.
- Runtime contains no names, roster sizes, or lore from a particular game.
- Local model execution is allowed only through an external Modly extension;
  the OpenAI route is likewise external authoring, never runtime inference.
- Game repositories live outside the Forge, pass the clean-game boundary
  audit, and distribute only game-owned runtime code plus approved immutable
  bundles and processed assets.
- Runtime bundles likewise use standalone external roots; neither export nor
  import accepts a bundle nested in Forge, world, bundle, or game storage.
## Composed game releases

M6 adds an additive composed-release catalog beside the unchanged legacy world
catalog. Generated games independently verify immutable composed bundle
inventories and correlations before using their worldpack for deterministic
headless simulation, saves, replays, package creation, extraction, and replay
from the extracted package. Presentation-neutral persistence stays keyed to the
world/release rather than to a representation variant. A pure composition plan
orders world base, world overlay, and UI overlay by layer and slot while audio
remains a separate sequence.

Native dispatch is a narrower code-owned authorization. The retained legacy
`isoworld_raylib_2_5d` adapter and the additive bounded generic 2D puzzle and
2D/text narrative adapters are separate code-owned implementations; each may be
selected only when its exact platform and runtime-support evidence authorize the
immutable logic/runtime bundle being consumed. Unsupported presentations or
required capabilities fail closed before importing pyray or opening a window.
The `pyray_3d_v1` proof is not dispatchable because the required collision
capability is absent. See
[ADR-0020](decisions/0020-composed-release-game-consumer.md).

The complete local M6 implementation evidence is still only partial readiness.
Composition and engine-neutral 3D authoring do not prove collision, physics,
navigation, representative performance, cross-platform native behavior, or a
full 3D runtime release. See
[AUDIT_M6_2026-07-24.md](AUDIT_M6_2026-07-24.md).

### Agent Harness contract foundation

Slice 1B.1 additively advances the historical Slice 1A plan with only immutable
worker activation and capability-grant lineage documents. They bind fresh-context
activation to role, work order, runtime, prompt and input identities. Grant
effective sets are the policy/role/work-order intersection. Validators do not
claim execution, isolation, authority, replay, or evidence quality.

Slice 1B.2 adds immutable event-log lineage and identity-only execution receipts.
Event subjects bind exact activation, grant, or supplied receipt identities;
the reserved memory-projection subject format does not publish a
`MemoryProjection` contract. Receipts bind exact activation, grant, runtime,
prompt, bounded invocation, artifact, outcome, and usage identities. These
documents still do not prove that execution or tool invocation occurred.

Slice 1B.3 adds an approved identity-only memory projection. It binds one exact
execution receipt, one or more exact source events, an explicit approved review
identity, and one or more hash-only decision, constraint, discovery, or
preference entries. It stores no memory text, prompt, transcript, rationale,
provider payload, executable content, or operational path. The artifact neither
mutates Engram nor infers that projected content is true.

The provider-free Agent Execution Kernel foundation is an internal synchronous
state machine and default-deny capability broker over those unchanged public
contracts. A dedicated, host-supplied private SQLite `AgentEventLog` implements
the journal boundary independently of `StudioStore`: it durably begins an exact
request, appends a bounded hash chain with generation/sequence/head CAS,
atomically records the receipt and terminal event, and revalidates immutable
audit records after reopen. Ordinary stores hold a shared retained one-byte OS
lock before SQLite opens; only a dedicated exclusive offline recovery store can
mark an orphaned or indeterminate open prefix `recovery_required`. Lock identity
is bound into the exact private v1 schema, whose canonical DDL, relational
shape, and startup foreign-key projection are fail-closed. Unsealable private
input has a null non-replayable fingerprint; a retry conflicts rather than
deduplicating. Replay performs no adapter side effects and never resumes work
or synthesizes a receipt/private output. Local spawned-process evidence covers
the POSIX fence; Windows shared/exclusive and remote-drive policy is seam-tested
but has no native evidence in this slice. Public receipt
`replay_support` remains `not_claimed` because audit reread is not provider
replay. Durable Studio job recovery, production-grade provider sandboxing, real
providers/models/billing, external MCP safety, memory approval/projection,
artifact promotion, Studio jobs/UI/Team Mode, deterministic provider replay,
and hosted/native/release evidence remain unimplemented and unproven.

A private Linux-only one-shot supervisor now replaces the in-process boundary
only for one fixed non-production conformance runtime. The child has no tools, proposal
ports, event log, Studio handles, authoring roots, or runtime authority. A
length-prefixed canonical JSON protocol uses per-spawn HMAC correlation and
an identity hash pinned to the actual bootstrap template. The worker validates
the complete authenticated request before action dispatch, and broker control
requires exact per-kind documents plus clean EOF after its sole terminal frame.
Linux delegates the worker to a fresh code-owned subreaper broker, holds worker
creation behind an authenticated parent acknowledgement, and accepts a result
only after a PID/start-time/state tracked
freeze/rescan/kill/reap fixed point proves the descendant domain empty. Linux
STOP/KILL operations are bound to retained, identity-validated `pidfd` handles;
pidfd unavailability or signaling failure is containment uncertainty rather
than permission to fall back to PID signaling. A lost
broker instead leaves the durable execution open for offline recovery; cleanup
of descendants still attributable to known worker identities is best-effort and
does not upgrade that uncertainty. Scratch ownership and final cleanup remain in
the parent. On Windows and every other unsupported host, supervisor construction
fails closed with `worker_containment_unavailable` before durable execution
begin or any broker, process, or provider authority is created. There is no
Windows worker backend in version 1, and Windows support and native evidence are
`UNTESTED`. A future reviewed Windows slice requires a custom `CreateProcess`
launcher that acquires containment ownership at creation before provider code
can run, followed by native Windows evidence. Same-UID filesystem/network
isolation, real providers, and telemetry enforcement remain outside this slice. See
[ADR-0031](decisions/0031-provider-free-agent-execution-kernel.md) and
[ADR-0032](decisions/0032-private-durable-agent-event-log.md), and
[ADR-0033](decisions/0033-one-shot-isolated-provider-worker.md).

The injected provider boundary is now bound to the existing activation runtime
triple rather than a Harness-selected registry entry. Kernel construction
strictly snapshots one exact built-in binding and the matching bound turn
callable before journal or broker authority can exist. A frozen private
authority rejects ordinary replacement or deletion, and later mutation of an
adapter's endpoint selector cannot redirect execution. This boundary does not
claim protection against `object.__setattr__`, malicious same-process
private/module reflection, or memory corruption. After durable begin,
cancellation and deadline retain precedence; an activation mismatch otherwise
terminalizes as the existing `provider_failed` failure without broker, provider,
worker, tool, or proposal activation. A matching turn and its receipt share that
exact binding, while exact-terminal replay performs no new binding access or
provider effect. The fixed supervisor's portable private ID is
`worldforge_conformance_provider`; a frozen private binding supplies fresh
caller-owned documents, and its content hash derives from the bootstrap template
built from the same immutable scalars. This adds neither a provider registry nor
selection authority. See
[ADR-0034](decisions/0034-exact-provider-runtime-attestation.md).

The next private Harness boundary adds instance-scoped human tool approval and
progressive definition exposure without widening the public contracts. A
canonical generation/hash-CAS review binds the execution, activation/grant and
private-input hashes, exact runtime and limits, and immutable eligible
descriptor catalog. Its decision is an approved ordered subset, denial, expiry,
or later revocation. The kernel fingerprints one atomic detached authority
snapshot before durable begin and never adopts a decision that arrives during
that begin. The reviewer ID is only an asserted in-memory label; Studio
authentication and durable approval evidence are not implemented. The broker
requires adapter-supplied exact summary/schema metadata and gives the provider
only approved summary/hash pairs initially. Ordered unique exposure requests
preserve their first-request order and make full bounded canonical schemas
available on the next turn, never the current one. Any overlap between exposure
requests and calls in one result is rejected before all tool/proposal effects,
and all remaining tool/proposal authority is preflighted before the first
effect. Missing, hidden, incompatible, unapproved, revoked,
expired, and unexposed tools remain a non-oracle `tool_not_authorized` boundary.
Cancellation/deadline/duration and runtime mismatch retain precedence; incurred
usage and budgets are accounted before post-provider approval. Linux can stop a
blocked worker after revocation but still requires its existing process-domain
empty proof. Fingerprints bind catalog/review/decision hashes, exact terminal
duplicates remain evidence-only after revocation, and interrupted executions
are never resumed. Approval covers tools only, not providers, cloud, cost, data,
credentials, artifacts, or memory promotion. The private conformance runtime is
revision 2; Windows remains unsupported and `UNTESTED`. See
[ADR-0035](decisions/0035-human-approval-and-progressive-tool-exposure.md).

Slice 2B retains the closed, identity/evidence-only plan, observation, and report
boundary for an optional codebase-memory comparison and adds a pure evaluator
plus an explicit-input, atomic no-replace CLI. Validators resolve the exact plan
and complete task/repetition/arm observation inventory. The evaluator computes
only deterministic metrics and immutable gates from supplied recorded evidence;
it does not run the benchmark, query or refresh an index, inspect a checkout,
score content, or contact an MCP/provider. The fixtures are synthetic and
`not_evaluable`; no actual A/B/C benchmark has been run and no candidate has
been adopted. See
[`CODEBASE_MEMORY_BENCHMARK.md`](CODEBASE_MEMORY_BENCHMARK.md).
