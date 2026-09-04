# World Forge

[![License: MIT](https://img.shields.io/badge/License-MIT-lilac.svg)](LICENSE)

A deterministic authoring-to-execution toolkit for typed multi-genre creation
projects, immutable generic gamepacks, reviewed/sealed assets, bounded runtime
adapters, and standalone games. The existing RPG worldpack and tested
2D/2.5D `isoworld` pyray/raylib runtime remain a backward-compatible reference
specialization. Runtime data works without an LLM, AI API, or Internet
connection; runtime AI is forbidden.

This repository contains **the Forge**, not a particular world or game. A
generic creation repository may describe a game, universe library, or asset
library without forcing lore, actors, narrative, or an RPG structure. Retained
world-authoring repositories keep their published legacy workflow. A separate
game repository owns executable code, UX, imported immutable artifacts,
platform CI, and releases. No game-specific lore is hardcoded here.

AI can assist **outside the game** with experience design, mechanics, typed
content, worldbuilding or narrative when applicable, presentation, and assets.
Its output is never accepted directly: GPT orchestrates, a human or authorized
lead reviews, `worldforge` validates, and deterministic compilation/sealing
creates runtime artifacts. Prompts, providers, models, credentials, and mutable
authoring source never enter a distributed game.

## Planned foundation: Harness, Studio, Engine Lines, and Tool Center

Slice 1 records architecture and vocabulary only; it does **not** add an agent
harness, Team Mode, Engine Lines, `gamepack_runtime` SDK/ABI changes, a Tool
Center, provider execution, discovery, installation, or a new UI. Existing
Studio, gamepack, worldpack, runtime, and game contracts remain unchanged.

Team Mode requires exactly three distinct model lineages; if they are
unavailable, it must show a visible degraded mode and cannot claim consensus.
The Forge-independent `gamepack_runtime` kernel already exists. Slice 5 plans
only its additive formal SDK/ABI role and evolution. Its target materialized
external-game layout is editable `src/engine/` and `src/game/`, an exact
`engine.lock.json`, and an immutable `src/isoworld/` snapshot where the legacy
snapshot applies; the current scaffold remains unchanged until that slice.
The pyray boundary applies only within editable `src/engine/`; immutable legacy
`src/isoworld/` retains its published compatibility imports.

The baseline is `8334f2536ee03f541cbee7f729379139e70241df`. GitHub Actions are
intentionally absent. Each future slice is governed by applicable local
verification and an independent fresh review. `hosted_evidence` remains
`PENDING` and native evidence remains `UNTESTED` unless exact real evidence
exists; a local result never becomes a hosted or native pass. Returning CI is
separate, explicitly authorized, time-boxed work.

The planned authority and vocabulary are recorded in
[ADR-0026](docs/decisions/0026-world-forge-agent-harness.md),
[ADR-0027](docs/decisions/0027-virtual-studio-governance.md),
[ADR-0028](docs/decisions/0028-project-owned-engine-lines.md), and
[ADR-0029](docs/decisions/0029-tool-center-capability-workflow-run-model.md).

## Architecture lanes

### Generic creation lane

`world-forge.project` v1 and its composable profile lead through typed modules,
phase-report v3 P00-P14, `world-forge.gamepack` v1, generic D1-D3 assets,
capability-based runtime resolution, readiness/handoff, and bounded standalone
materialization. `worldforge new-creation` defaults to the backward-compatible
neutral `universe_library`, and can explicitly create an `asset_library` or a
`game`. A game requires independent gameplay, world, narrative, presentation,
and runtime-support facets; no runtime adapter is inferred from gameplay or
fiction, so the initial scaffold is authoring input rather than executable or
release evidence. If a bound upstream identity changes,
`worldforge reconcile-creation` uses the previously captured workflow
status hash as a CAS and appends canonical invalidation/history before any
status, reopen, or completion transition.

### Legacy RPG lane

Published `rpg-world-forge.*` project/source/asset contracts,
`isoworld.worldpack` v1-v5, saves, replays, bundles, and the bounded
`isoworld_raylib_2_5d` adapter remain readable and behaviorally separate. They
are not renamed or widened into a generic union.
The visible identity is World Forge, while Python imports and the CLI remain
`worldforge`; the repository remote is not renamed, and app-ID migration remains
future-gated behind explicit hosted, backup, divergence, retry, rollback, and
native Windows evidence.

Authoring validity is not runtime executability. See the central
[`docs/MULTI_GENRE_ARCHITECTURE.md`](docs/MULTI_GENRE_ARCHITECTURE.md) design
and exact [`docs/SUPPORT_MATRIX.md`](docs/SUPPORT_MATRIX.md) evidence levels
before interpreting a support claim.

## Current systemic slice (M5 complete)

- Canon-locked asset targets for 2D, 2.5D, or 3D, with approved visual/audio
  bibles, deterministic inventory derivation, and per-asset specifications.
- Hash-bound production requests and sanitized receipts for OpenAI Image,
  Blender MCP, and capability-discovered Modly extensions; GPT remains the
  orchestrator and provider tooling stays outside Forge and runtime code.
- Deterministic PNG canonicalization, atlas/clipset assembly, PCM WAV
  processing, strict TTF/OTF/GLSL validation, and recipe-bound receipt
  re-verification. Processing recipes remain v1; newly produced receipts are v2
  and bind the exact asset-root-relative recipe file, raw SHA-256, canonical
  content hash, inputs, operation, and output contract. Legacy v1 receipts
  remain identity-only readable.
- Provider-neutral GLB inspection and runtime-only `assetpack_v1` handoff for
  3D targets, plus a two-step build/hash-seal release lifecycle. The pyray
  reference runtime and current immutable game bundle remain explicitly
  2D/2.5D renderpack consumers.
- Thirteen bounded M5 skills covering OpenAI/Codex 2D/2.5D production,
  reference-led Blender modeling/rigging/animation/export, independent 3D QA,
  and fail-closed Modly operation/refinement.

The committed [`examples/m5-neutral`](examples/m5-neutral/) fixture is
**narrative-neutral**, local, procedural, and offline. Its schema-required
`openai` route value is a contract namespace; no provider, model, or network
call executes. The committed manifests are authoring-side `production`
evidence, not runtime packs. Readiness gates regenerate the fixture externally
and build/verify temporary renderpack and assetpack outputs, finalize copied
manifests, and validate their release profiles without committing those runtime
packs.

- Atomic v2 creation, inspection, cloning, explicit legacy upgrade, and
  optimistic-lock SemVer versioning for independent world repositories.
- Worldpack v5 with typed BCP47 localization, per-playable-actor campaigns,
  and pure runtime API/feature compatibility checks; v1-v4 remain loadable.
- Deterministic runtime-only bundles with complete hashes/licenses, portable
  paths, provider/authoring-metadata rejection, and stable SemVer releases.
- Atomic multi-world/multi-release game import under a runtime-neutral locked
  catalog, with rollback and verification of every existing release.
- Clean standalone game materialization with a locked `isoworld` snapshot,
  separate pyray platform lock, exact `raylib==6.0.1.0` baseline, independent
  verifier, native smoke, benchmark, deterministic package, and desktop CI.
- Canonical `game_data/shared.lock.json` for game-owned common presentation
  assets, including byte/media validation and a hash-bound notices contract.
- Forty-six Forge-only skills: nine bounded generic creation/gamepack/asset/
  runtime/handoff workflows plus retained one-operation legacy world, M5, and
  pyray specializations, with no all-in-one game-building skill.
- Enforced immutable seams: game extensions live under `src/game`; vendored
  runtime snapshots and imported bundles change only through dedicated Forge
  operations.

- Fixed-step game loop rendered through pyray.
- Isometric projection and semantic terrain (ground, water, and rock).
- Reactive state updates through actions and a deterministic reducer.
- Strict `WorldState -> immutable RenderState -> Renderer` separation.
- World-defined playable and non-playable actors; no hardcoded roster.
- Deterministic A* navigation, occupied-cell collision, and route reservations.
- Configurable world clock and schedules with ordered fallback destinations.
- Contextual interactions with flag/resource effects.
- Abilities with explicit resource costs, range, cooldowns, and effects.
- Versioned, worldpack-bound saves and deterministic action replays.
- Finite Tiled JSON and embedded LDtk JSON map import.
- Typed facts, rumors, secrets, and enforced per-actor knowledge boundaries.
- Directed relationship dimensions and per-actor faction reputation.
- Conditional dialogue graphs with fact-gated speakers and choices.
- Event-reactive quest stages and prioritized time-windowed scenes.
- Construction blueprints with footprints, costs, build time, dynamic collision,
  render bindings, and narrative events.
- Typed resources, located stockpiles, bounded capacity, production recipes,
  delayed outputs, and derived scarcity.
- Per-actor needs with deterministic decay and hierarchical, prioritized goals
  that can travel, consume, build, or produce.
- Persisted delayed consequences that react to domain events and form bounded,
  authored multi-stage arcs.
- Offline narrative reachability, producer, and softlock analysis.
- Offline content compiler and cross-reference validator.
- Offline asset pipeline with provenance and license tracking.
- Target-scoped asset manifest v3 with hash-bound specifications, complete
  receipt lineage, multi-file processed outputs, semantic bindings, and strict
  OpenAI/optional-Modly generation routes.
- Runtime-only hashed renderpacks compiled without prompts, model data,
  workflows, credentials, or production evidence.
- Pyray resource registry for textures, clipsets, fonts, shaders, SFX, and
  streamed music with deterministic cleanup.
- Texture-backed isometric tiles/actors, tick-based animation, depth layers,
  portraits, event audio, and zoom/pan camera with primitive fallbacks.
- A 15-phase workflow with GPT as lead agent and verifiable quality gates.
- Runtime audit that rejects AI SDK imports.
- Headless tests that do not open a window.

The included foundation pack is a **neutral technical vertical slice**. Real
worlds live in independent world-authoring repositories and can define
different actors, genres, rules, maps, languages, and campaigns without
changing the Forge. Independent game repositories import only immutable,
hash-locked releases.

## Current M6 slice (partial)

**PARTIAL — local implementation evidence only. Self-contained Studio release
remains blocked; a push alone cannot create hosted or native evidence. Those
states remain `PENDING`/`UNTESTED` until a separately authorized real
hosted/native evidence process exists and passes.**

The canonical generic release-lineage command is
`python -m scripts.verify_multigenre_release --native off --report <external>`.
On a supported v1 headless host (Linux x86_64 or Windows x86_64 with CPython
3.11/3.12), it exercises both executable multi-genre fixtures through
deterministic compile, real PNG/TTF processing and QA, sealing,
runtime/materialization, standalone verification, headless save/replay, package
reproducibility, and extraction. `off` truthfully records native execution as
untested. ARM64 hosts can run lower-level logic/unit checks, but cannot mint v1
headless/release evidence or publish a passed deterministic release report.
GitHub Actions are intentionally absent at the Slice 1 baseline. Existing hosted
evidence remains **PENDING**; local results and workflow definitions are
not hosted or native evidence. Returning CI requires separately authorized,
time-boxed work. The authoritative machine-readable status is
`docs/evidence/multigenre-release-status.json`.

The executable end-to-end fixtures are `abstract-puzzle` and
`branching-narrative`; hosted native evidence for the exact reviewed revision
is still pending. Four additional cases—`action-framing`, `faction-strategy`,
`modular-roguelite`, and `sports-career`—prove authoring breadth only. Each has
an exact authored gamepack and 16-file real asset production/QA lineage, but its
ledger remains `authoring_only` / `adapter_not_evaluated`; adapter execution,
packaging, and release are unproved and blocked. Across all six asset-bearing
cases the D2 fixture census is 96 files. A `release_ready` manifest is not a
sealed assetpack or a released game. The separate `systemic-simulation` case
has assets `not_applicable` while runtime is requested, so runtime remains
blocked rather than receiving placeholder assets.

- Forge Studio provides interactive World/lore, Assets, and Game cockpits over
  one durable local service. Source proposals remain exact reviewed changesets;
  neither Codex nor a provider can approve or apply them.
- Generic Studio editing and fixed controls for compile, asset process/seal,
  PNG/WAV preview, runtime compose/bundle, materialization bundle/standalone,
  package, extraction, and headless evidence publication are implemented and
  locally tested. Protocol v5 keeps exactly 18 transport methods; job/worker
  reaches v12, output grants reach persisted v6, and previews remain published
  v1 plus QA-candidate v2. Historical v3 create rejects `asset_content_mode`;
  v5 create accepts `asset_content_mode` so asset content mode and runtime
  support intent are orthogonal. The v5 handshake exposes only the four activated
  authority capabilities: `asset_authority_reviews`,
  `asset_release_authority`, `runtime_headless_authority`, and
  `creation_preview_pre_release`. This is not hosted, packaged-shell, native,
  or release evidence.
- Machine-readable capability, presentation, adapter, composition, and
  compatibility contracts support 2D, 2.5D, 3D, and mixed world-plane plans.
  Static adapter resolution and immutable composed bundles never turn contract
  data into an executable locator.
- Generic gamepack assets now traverse reviewed planning and production into
  closed deterministic processing, retained-byte QA, and a
  `world-forge.asset_manifest` v1 state of `produced`, `processed`, or
  `release_ready`. The single `validate-generic-asset-contract` command and
  Studio validator dispatch all fourteen authoring formats. D3 then seals only
  an exact `release_ready` lineage into a separate `world-forge.assetpack` v1
  runtime directory. Its integral verifier binds the canonical manifest,
  processed payloads, public notices, exact byte/media constraints, and nested
  inventory to one immutable hash. A sealed pack is still not runtime
  compatibility, adapter execution, bundle composition, or release evidence.
- Generic puzzle and branching-narrative bundles can now be exercised through
  canonical `world-forge.game_execution_script` v1 scenarios. The
  Forge-independent headless kernel proves deterministic transitions plus
  save/restore/replay continuity, then publishes an external immutable
  `world-forge.headless_evidence_set` v1. This remains non-native evidence:
  `native_execution` is false, Studio inspection delegates semantics to its
  packaged Python runtime, and release stays blocked.
- The exact same runtime bundles can now be opened by bounded
  `gamepack_raylib_2d_puzzle@1.1.0` and
  `gamepack_raylib_2d_text@1.1.0` implementations. A fixed 60 Hz controller,
  semantic keyboard/pointer input, exact sealed PNG/TTF loading, and a
  deterministic recording backend prove local render behavior without
  importing the Forge. The narrative adapter renders only compiled authored
  English text with the sealed font; the puzzle adapter adds shape, number, and
  text feedback rather than relying on color alone.
- Generated standalone games can install and independently verify composed
  releases, then run representation-neutral headless, save, replay, package,
  extraction, and extracted-package workflows without `worldforge`.
- Native-verified presentation is still limited to the exact legacy Linux
  x86_64 2.5D adapter. The new bounded 2D adapters isolate their lazy `pyray`
  import behind the backend and fail closed on undeclared hosts, but fake
  backend tests are not native evidence. The pyray GLB proof deliberately lacks
  collision and remains
  incompatible with every current 3D/mixed profile; it is not a playable 3D
  runtime or representative performance evidence.
- Exact Studio runtime provenance, secure acquisition, deterministic synthetic
  assembly, and shell-package verification are implemented. Verified
  `shell_only` packages exclude Python and Codex, retain all seven open
  legal/provenance blockers, and state `release_ready=false`.

### Deterministic standalone package boundary

`world-forge.game_package` v1 is the immutable transport for one already
materialized generic standalone game. `package-game` publishes a canonical
ZIP_STORED archive without replacement, and `verify-game-package` checks the
archive metadata, manifest, complete byte inventory, standalone lock, and
lineage before any extraction write. `extract-game-package` then publishes an
exact verified tree through an identity-bound Linux/Windows journal.
`recover-game-package-extraction` resumes only the recorded immutable tree;
`rollback-game-package-extraction` removes only a proven unpublished stage.
Ambiguous ownership or changed hashes fail closed and preserve evidence.

The Forge transaction never executes game-local `scripts/verify_game.py`.
That script is a separate post-extraction check run from a disposable game
context without Forge mutation authority. Package integrity, extraction,
headless execution, and replay evidence are independent: the resulting game
still reports `release: blocked` while hosted native evidence is absent.

The full evidence, exclusions, and remaining gates are recorded in
[AUDIT_M6_2026-07-24.md](docs/AUDIT_M6_2026-07-24.md). Self-contained artifact
publication, signing, and runtime-download CI are intentionally absent; see
[ADR-0021](docs/decisions/0021-studio-runtime-distribution-boundary.md).

## Forge Studio application service

Forge Studio v1 begins with a local, provider-free Python application service.
It preserves the separate Forge, world-authoring, bundle, and game repository
roots while giving a future desktop client one strict interface for durable
workspace registration, events, job state, and explicitly approved source
changesets. It does not run models, providers, Blender, Modly, watchers, or the
graphical game runtime. Its only executable jobs are offline receipt validation,
world-anchored assetpack verification, deterministic headless runtime ticks,
and deterministic replay verification.

Start the service with an explicit user-data directory outside every project:

```bash
worldforge-studio-service --data-dir /path/to/user-data/rpg-world-forge-studio
```

The process reads and writes one strict UTF-8 JSON object per line on standard
input/output. Public v1 request methods are `service.initialize`,
`workspace.register/list/get/overview`, `source.list/read`,
`asset.catalog.list/inspect`, `asset.preview.open/read/close`,
`world.validate/analyze`, `events.list`,
`changeset.create/get/list`, `changeset.diff/approve/reject/apply`, and
`job.create/get/list/transition/cancel`.
Contract errors are returned as correlated `error` envelopes; a malformed line
does not terminate the stream.

`job.create` is a closed operation-specific contract that writes managed v2 job
records. Paths are portable and relative to the registered world
(`asset.receipt.validate` is relative to `world_root/assets`), and
`runtime.headless` accepts integer ticks from 0 through 1,000,000. Previously
stored v1 jobs remain readable, recoverable, listable, and cancelable, but are
never claimed or retried. A single durable FIFO scheduler runs eligible v2 jobs
in a fixed isolated worker; no job can select an executable, module, working
directory, root, argument vector, or environment. `job.cancel` records durable
intent, and a running managed job becomes canceled only after its process tree
has been terminated and reaped.

The read-only authoring methods expose only manifest-declared world source
documents. They return portable paths and hashes from bounded, pinned reads;
never absolute repository paths. Validation and narrative analysis reuse the
existing Forge domain logic entirely in memory and do not publish reports.
The Electron preload exposes these reads and the four offline jobs only as
named capabilities. Its two asset catalog methods bind pagination and
inspection to an exact manifest revision; Electron main owns the 64-entry page
limit, protocol methods, operation names, request IDs, and timeouts. Renderer
input cannot supply catalog paths, media types, categories, cursors, binary
payloads, or arbitrary parameters. Three separate preview methods authorize
only manifest-selected PNG/WAV entries and sequential 64 KiB chunks. Their
arguments contain only revision/entry identity or an opaque handle/sequence;
Electron main validates stream correlations, strips canonical protocol base64,
and returns fresh `Uint8Array` bytes through the named preload boundary. No
preview UI is introduced by this service boundary.
The World cockpit groups those authorized sources, keeps drafts only in memory,
checks JSON syntax, and renders bounded neutral map previews on Canvas. A dirty,
syntax-valid draft can be explicitly staged as one exact base-hashed replacement
for human review; it is never autosaved or written directly. The cockpit opens
the returned immutable v2 text and JSON Pointer diff, requires separate approve
and apply confirmations, and refreshes verified sources only after apply
succeeds. Legacy v1 records remain readable with exact diff unavailable; the
desktop does not offer fresh v1 approval or apply. The World, Assets, and Game
cockpits share a responsive accessible keyboard tablist; inactive panels remain
mounted so an in-memory World draft survives discipline changes.
The read-only Assets cockpit lazily loads one revision snapshot, replaces pages
under exact revision-bound next/previous controls, filters categories only
within the current page, and displays bounded JSON/GLSL or verified
PNG/WAV/font/GLB metadata. Authorized PNG/WAV entries may use the bounded
revision-bound preview lease; no arbitrary file access or 3D rendering is
introduced.
The Game cockpit exposes exactly three existing fixed jobs: engine-neutral
assetpack metadata/handoff verification, reference-runtime headless simulation
for 0 through 1,000,000 ticks without graphics, and verification of an existing
replay action log. Its paths are blank, portable, and relative to the selected
workspace. The result view accepts only valid v2 records for that workspace,
shows structured inputs, state, timestamps, results, and observed progress, and
never displays raw payloads, worker output, or repository roots. The bounded
job view is not chronological. It does not record replays, use generated-game
slots, launch a game, create a bundle/package, or claim an M6 3D runtime.

Changesets edit only UTF-8 files beneath a registered world's `source/`
directory. New v2 records retain the exact base and proposed snapshots in
content-addressed storage under the external data directory and bind their
ordered operation descriptors with `review_sha256`. Exact bounded text hunks,
with a strict-JSON Pointer supplement when applicable, are derived only from
those retained bytes. A v2 approve, reject, or apply must echo the reviewed
hash. Apply durably claims `applying` before any repository mutation, rechecks
every base hash and filesystem identity under the world lifecycle lock, and
uses a review-bound journal so an interrupted multi-file apply is completed or
rolled back without claiming cross-filesystem atomicity. Existing v1 records
remain actionable but report that exact base review bytes were not retained.

The public contracts are
[`forge-workspace`](schemas/forge-workspace.schema.json),
[`studio-protocol`](schemas/studio-protocol.schema.json),
[`studio-changeset`](schemas/studio-changeset.schema.json), and
[`studio-job`](schemas/studio-job.schema.json). The application boundary is
recorded in [ADR-0011](docs/decisions/0011-forge-studio-application-service.md),
with immutable review evidence and apply claiming specified by
[ADR-0015](docs/decisions/0015-studio-reviewable-changesets.md).

The desktop shell lives in [`apps/studio`](apps/studio). It is a sandboxed
Electron client that loads only `rwf-studio://app`, exposes named typed preload
operations, and supervises both the Python service and an optional exact Codex
0.144.6 app-server without a shell or `PATH` fallback. Codex is bound to one
registered workspace and can only stage or inspect changesets through the
three-tool Forge MCP boundary; approval and apply remain human-controlled.
Development requires explicit `WORLD_FORGE_STUDIO_DEV_PYTHON` and
`WORLD_FORGE_STUDIO_DEV_CODEX` executables. Deprecated `RWF_STUDIO_*` aliases
remain accepted only when their values do not conflict with canonical names;
unequal dual values fail closed.
Native packaged runtimes and the broader
visual authoring tools remain separate release slices. The current package
workflow builds and statically verifies only an external `shell_only` tree with
Python and Codex absent. The self-contained path is fail-closed by the checked-in
runtime provenance contract and cannot publish while its seven blockers remain
open; see
[ADR-0012](docs/decisions/0012-forge-studio-desktop-shell.md) and
[ADR-0013](docs/decisions/0013-workspace-bound-codex-bridge.md), plus the
distribution decision in
[ADR-0021](docs/decisions/0021-studio-runtime-distribution-boundary.md).

## Quick start

```bash
python -m venv .venv
python -m pip install -e ".[game]"
worldforge validate examples/foundation/source/manifest.json --profile release
worldforge compile examples/foundation/source/manifest.json \
  --output content/compiled/foundation.worldpack.json
isoworld --pack content/compiled/foundation.worldpack.json
```

Without installing the package:

```bash
PYTHONPATH=src python -m worldforge validate \
  examples/foundation/source/manifest.json --profile release
PYTHONPATH=src python -m isoworld \
  --pack content/compiled/foundation.worldpack.json
```

Vertical-slice controls:

- Arrow keys or WASD: move one cell.
- Left click: plan an A* route to a cell.
- `Tab`: select the next playable actor defined by the worldpack.
- `E`: use the nearest available contextual interaction.
- `1`: use the active actor's first ability.
- `Q`: start the nearest eligible dialogue; number keys select a choice.
- `Esc`: leave a dialogue when its current node allows it.
- `Space`: dismiss an active scene.
- `F5`/`F9`: write/load the path supplied with `--save`.
- `Esc`: exit.

Save a run and record a replay:

```bash
isoworld --pack content/compiled/foundation.worldpack.json \
  --save saves/quick.json \
  --save-on-exit saves/latest.json \
  --record-replay saves/latest.replay.json

isoworld --pack content/compiled/foundation.worldpack.json \
  --replay saves/latest.replay.json
```

Saves and replays are tied to the exact world content hash. A changed worldpack
is rejected instead of silently loading incompatible state.

M3 exposes `build`, `start_production`, and `transfer_resource` as typed
`GameAction` values. A derived game supplies its own build/economy UI and
dispatches those actions; the forge runtime deliberately does not impose a
genre-specific construction menu. Completed or in-progress constructions are
visible in the pyray renderer, with `construction:<blueprint_id>` renderpack
bindings and primitive fallbacks.

## Create an independent world

The scaffold asks for only the decisions required to create a safe draft. It
does not invent lore or characters:

```bash
worldforge new-world ../my-world \
  --id my_world \
  --title "My World" \
  --language en \
  --version 0.1.0

worldforge world-status ../my-world
worldforge phase-status ../my-world
worldforge validate ../my-world/source/manifest.json --profile draft
```

`../my-world` is an independent **world-authoring repository**, not a game
repository. It includes `AGENTS.md`, 15 ordered phases, decision and task logs,
multi-agent claims, phase reports, narrative source directories, and an
asset-production workspace. GPT can run the entire process as lead agent;
specialist roles are optional.

World identity and lineage operations are explicit:

```bash
worldforge clone-world ../my-world ../another-world \
  --id another_world --title "Another World" --version 0.1.0
worldforge bump-world-version ../my-world \
  --expected-version 0.1.0 --part minor \
  --reason "Add a reviewed campaign" --approved-by lead-agent
```

New world projects use the retained `rpg-world-forge.project` discriminator at
format version 3 with `tool_repository="world-forge"`. Existing version 2
projects remain readable without mutation. Migrate one explicitly by hashing
the exact current `.worldforge/project.json` bytes, reviewing a side-effect-free
dry run, and then applying the same compare-and-swap source hash:

```bash
worldforge migrate-world-project ../legacy-world \
  --expected-source-hash <sha256-of-exact-project-json-bytes> --mode dry-run
worldforge migrate-world-project ../legacy-world \
  --expected-source-hash <same-sha256> --mode apply
```

A clean dry-run also reports `apply_supported` and an exact
`apply_capability_reason` without creating a lock or migration artifact. If a
durable migration record is already present, dry-run validates its immutable
backup and journal boundary and reports recovery required instead of claiming
fresh-apply readiness. Linux uses an identity-checked `RENAME_EXCHANGE`
transaction. Windows apply is bounded to build 20348 or newer and a
capability-proven local NTFS volume: retained 128-bit file identities and
no-delete ancestry handles seal the source, a durable hard link retains its
original identity, and `FileRenameInfoEx` publishes the target with
commit-forward recovery. Windows never simulates rollback after an ambiguous
rename; unsupported or indeterminate states fail closed and preserve evidence.

Legacy format version 1 remains a separate explicit `upgrade-world` to version
2 operation. Ordinary loads never upgrade or migrate a project.

After the canon is complete:

```bash
worldforge compile ../my-world/source/manifest.json \
  --output ../my-world/build/my_world.worldpack.json
worldforge analyze-narrative ../my-world/source/manifest.json \
  --output ../my-world/build/narrative-analysis.json \
  --fail-on warning
worldforge init-assets ../my-world/build/my_world.worldpack.json \
  --target-dimension 2_5d \
  --output ../my-world/assets/manifest.json

# Optional and fail-closed: add only after reviewing the installed Modly stack.
# Omit this flag to keep the local route and executor disabled.
worldforge init-assets ../my-world/build/my_world.worldpack.json \
  --target-dimension 3d --enable-modly \
  --output ../my-world/assets-3d/manifest.json

# After authoring and approving target-bound visual/audio bibles:
worldforge validate-asset-bibles \
  --target ../my-world/assets/target.json \
  --visual ../my-world/assets/bibles/visual.json \
  --audio ../my-world/assets/bibles/audio.json
worldforge derive-asset-inventory \
  ../my-world/build/my_world.worldpack.json \
  --target ../my-world/assets/target.json \
  --visual-bible ../my-world/assets/bibles/visual.json \
  --audio-bible ../my-world/assets/bibles/audio.json \
  --output ../my-world/assets/inventory/assets.json

# Execute one reviewed recipe, then re-verify its exact recipe and outputs.
worldforge process-asset ../my-world/assets/recipes/portrait.json \
  --asset-root ../my-world/assets \
  --output-directory ../my-world/assets/processed/portrait
worldforge verify-processing \
  ../my-world/assets/processed/portrait/processing.receipt.json \
  --asset-root ../my-world/assets

# After every required asset has complete production, processing, license, and
# QA evidence, the builder validates the manifest's production/build profile:
worldforge build-renderpack ../my-world/assets/manifest.json \
  --worldpack ../my-world/build/my_world.worldpack.json \
  --output ../my-world/assets/release/renderpack.json

# Seal that exact deliverable into the manifest, then validate the release:
worldforge finalize-asset-release ../my-world/assets/manifest.json \
  --deliverable ../my-world/assets/release/renderpack.json \
  --worldpack ../my-world/build/my_world.worldpack.json \
  --expected-hash <production-manifest-content-hash>
worldforge validate-assets ../my-world/assets/manifest.json \
  --profile release \
  --worldpack ../my-world/build/my_world.worldpack.json

# Optional reference-runtime preview only; this is not the game handoff:
isoworld --pack ../my-world/build/my_world.worldpack.json \
  --renderpack ../my-world/assets/release/renderpack.json
```

For a 3D target, replace `build-renderpack` with `build-assetpack` and write
`../my-world/assets/release/assetpack.json`; verify it with
`worldforge verify-assetpack`, then use the same `finalize-asset-release` and
release-validation steps. The assetpack is an engine-neutral implementation
handoff. The current `isoworld` reference runtime, `export-bundle`, and generated
standalone game consume only the 2D/2.5D renderpack path; a 3D game must add and
validate its own runtime adapter before importing the assetpack. This milestone
boundary is defined by
[ADR-0010](docs/decisions/0010-m5-asset-production-and-m6-3d-runtime-boundary.md).
The closed assetpack contains no license or authoring metadata. Required runtime
licenses and notices travel beside it as separately verified immutable-handoff
material.

The current 2D/2.5D production handoff becomes an immutable runtime bundle.
Forge-side tooling verifies and copies that bundle into a separate game
repository. It never copies the world's `AGENTS.md`, `.worldforge/`, editable
`source/`, production manifests, prompts, candidates, or model/provider
metadata.

```bash
worldforge export-bundle \
  ../my-world/build/my_world.worldpack.json \
  ../my-world/assets/release/renderpack.json \
  ../releases/my_world-1.0.0 \
  --release-id 1.0.0 \
  --licenses ../my-world/assets/release/licenses

worldforge verify-bundle ../releases/my_world-1.0.0 \
  --expected-hash <bundle-sha256>

worldforge new-game ../my-game \
  --id my_game --title "My Game" --source-revision <forge-commit>
worldforge import-bundle ../releases/my_world-1.0.0 ../my-game \
  --expected-hash <bundle-sha256>
worldforge audit-game ../my-game
```

Generic gamepacks use the separate, additive pre-execution bundle contract:

```bash
worldforge build-game-runtime-bundle \
  ../project/artifacts/game.gamepack.json \
  ../project/assets/inventory.json \
  ../project/assets/release/assetpack \
  --snapshot ../runtime/snapshot.json \
  --registry ../runtime/registry.json \
  --composition ../project/runtime/composition.json \
  --support-report ../project/runtime/support-report.json \
  --output ../releases/game-runtime-bundle

worldforge verify-game-runtime-bundle \
  ../releases/game-runtime-bundle \
  --expected-hash <bundle-content-hash>

worldforge inspect-runtime-implementation \
  ../project/runtime/runtime-implementation.json

worldforge inspect-runtime-platform-lock \
  ../runtime/platform-locks/<lock-id>.json

worldforge build-game-materialization-bundle \
  ../releases/game-runtime-bundle \
  ../project/runtime/runtime-implementation.json \
  --platform-lock ../runtime/platform-locks/<linux-cp311-lock-id>.json \
  --platform-lock ../runtime/platform-locks/<linux-cp312-lock-id>.json \
  --platform-lock ../runtime/platform-locks/<windows-cp311-lock-id>.json \
  --platform-lock ../runtime/platform-locks/<windows-cp312-lock-id>.json \
  --output ../releases/game-materialization-bundle

worldforge verify-game-materialization-bundle \
  ../releases/game-materialization-bundle \
  --expected-hash <materialization-bundle-content-hash>

worldforge verify-game-save \
  ../user-data/saves/<game-id>/<bundle-id>/slot.json \
  --bundle ../releases/game-runtime-bundle

worldforge verify-game-replay \
  ../user-data/replays/<game-id>/<bundle-id>/run.json \
  --bundle ../releases/game-runtime-bundle

worldforge verify-persistence-generation \
  ../user-data/saves/<game-id>/<bundle-id>/slot.slot/v1/generations/<sequence>-<hash>.json \
  --bundle ../releases/game-runtime-bundle
```

Bundle success proves exact transfer integrity only. Additive
`world-forge.game_save` v1 and `world-forge.game_replay` v1 documents bind the
exact gamepack, runtime composition, runtime bundle, neutral runtime API, and
execution-semantics hash. Saves contain only the declared saved-state
projection; restore reconstructs transient state from the immutable initial
state. Replays contain accepted actions only and verify every pre-state,
post-state, event, trace, final-state, and classification hash.
`world-forge.persistence_generation` v1 stores either unchanged payload in an
append-only, content-addressed DAG. Logical slot writes stage outside the
authoritative generation inventory, publish with native no-replace semantics,
fsync the retained directory, and never replace history. Concurrent sibling
tips fail closed until an explicit all-tip resolution; rollback appends a
previously verified payload. Legacy `<slot>.json` files remain read-only
compatible and require explicit hash-anchored migration before appending.

Studio validates their structure in JavaScript but routes semantic verification
to packaged Python; it does not implement gameplay semantics. The bundle and
checked-in support reports still deliberately report `pre_execution`,
`release: blocked`, and `supported: false`. Standalone-game materialization and
deterministic packaging are implemented, but neither is native execution or
hosted platform evidence.

The additive materialization envelope closes implementation identity only. It
binds the unchanged runtime bundle to exact code-owned package projections,
semantic entry points, and the four audited `raylib==6.0.1.0` CPython
3.11/3.12 Linux/Windows x86-64 wheels. A policy-only envelope reports
`contract_only` and `materialization_ready=false`; the ready state reports
`materialization_ready: true`, embeds the exact launcher/verifier inventory, and
may create an external standalone game repository. Neither state installs a
wheel or provides native-platform evidence.

The game is a normal standalone project. It contains no agent files or
authoring control plane and verifies/runs without `worldforge` installed.

## Import a map

The M1 importer supports finite, uncompressed Tiled JSON tile layers and
embedded LDtk IntGrid/tile layers. Create a reviewed numeric-to-semantic tile
mapping first:

```json
{
  "0": "ground",
  "1": "ground",
  "2": "rock",
  "3": "water"
}
```

```bash
worldforge import-map references/garden.json \
  --format auto \
  --id garden \
  --display-name "Garden" \
  --mapping references/garden.tiles.json \
  --layer Ground \
  --output source/maps/garden.json
```

The output records source and mapping hashes. Imported terrain remains source
data and must pass `worldforge validate`; manual overrides take precedence.

## Verification

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m worldforge audit-contracts --source-root .
PYTHONPATH=src python -m worldforge audit-runtime src/isoworld
PYTHONPATH=src python -m worldforge audit-game /path/to/materialized-game
PYTHONPATH=src python -m scripts.verify_m5_release
```

The complete M5 release-readiness command requires a clean source tree and uses
only disposable directories outside the repository. It regenerates and closes
the narrative-neutral renderpack/assetpack paths, exercises offline standalone
bundle/replay/package behavior, builds reproducible wheel and sdist artifacts,
and audits clean isolated installs. Exact dependency versions are pinned, but
the requirement files do not provide hashes for every dependency and are not
described as fully hash-locked. GitHub Actions are intentionally absent at the
Slice 1 baseline. Hosted Ubuntu/Windows evidence remains `PENDING` until
separately authorized CI work produces exact real evidence.

## Repository layout

```text
src/isoworld/              reference runtime; never imports worldforge or AI SDKs
src/worldforge/            offline authoring, build, workflow, and QA tools
src/worldforge/templates/  clean standalone pyray/raylib game materialization
.agents/skills/            Forge-only, phase-scoped construction workflows
examples/                  foundation slice and narrative-neutral M5 evidence
content/compiled/          generated worldpacks used by the example runtime
authoring/prompts/         provider-agnostic authoring prompts
agents/                    orchestration, phases, roles, and quality gates
schemas/                   public source, workflow, and asset contracts
docs/                      architecture, narrative model, ADRs, and roadmap
tests/                     headless tests and architectural boundaries
```

Read [ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[CONTENT_PIPELINE.md](docs/CONTENT_PIPELINE.md) before adding systems or canon.
M1 runtime contracts and limits are documented in
[M1_SYSTEMS.md](docs/M1_SYSTEMS.md), and the implementation audit is recorded in
[AUDIT_2026-07-19.md](docs/AUDIT_2026-07-19.md).
M2 narrative contracts and limits are documented in
[M2_NARRATIVE.md](docs/M2_NARRATIVE.md), with its security and implementation
review in [AUDIT_M2_2026-07-19.md](docs/AUDIT_M2_2026-07-19.md).
M2.5 presentation and renderpack contracts are documented in
[M2_5_PRESENTATION.md](docs/M2_5_PRESENTATION.md), with the implementation audit
in [AUDIT_M2_5_2026-07-19.md](docs/AUDIT_M2_5_2026-07-19.md).
The M4 repository boundary is defined by
[ADR-0009](docs/decisions/0009-independent-world-and-game-repositories.md), and
the multiple-world lifecycle, bundle, catalog, and game scaffold are documented
in [M4_MULTIPLE_WORLD_PRODUCTION.md](docs/M4_MULTIPLE_WORLD_PRODUCTION.md).
The corresponding adversarial implementation review is recorded in
[AUDIT_M4_2026-07-19.md](docs/AUDIT_M4_2026-07-19.md).
The one-skill-per-phase game workflow is defined in
[GAME_IMPLEMENTATION_PHASES.md](docs/GAME_IMPLEMENTATION_PHASES.md), and
the supported game-runtime conventions are documented in
[PYRAY_RUNTIME_GUIDE.md](docs/PYRAY_RUNTIME_GUIDE.md).
Visual and audio production is described in
[ASSET_PIPELINE.md](docs/ASSET_PIPELINE.md), including the 3D/Blender and
capability-gated Modly routes. The M5/M6 boundary is fixed by
[ADR-0010](docs/decisions/0010-m5-asset-production-and-m6-3d-runtime-boundary.md),
and the local pre-push implementation/readiness evidence is recorded in
[AUDIT_M5_2026-07-21.md](docs/AUDIT_M5_2026-07-21.md). Partial M6
implementation evidence is recorded separately in
[AUDIT_M6_2026-07-24.md](docs/AUDIT_M6_2026-07-24.md); it does not revise M5 or
claim self-contained Studio or complete 3D runtime readiness. The GPT and
multi-agent protocol is documented in [agents/README.md](agents/README.md).

The generic taxonomy and complete data flow are centralized in
[MULTI_GENRE_ARCHITECTURE.md](docs/MULTI_GENRE_ARCHITECTURE.md); current
contract/local/native/hosted truth is in
[SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md). The additive compiler/runtime
seams are recorded in
[ADR-0023](docs/decisions/0023-authoring-contracts-and-runtime-adapters.md) and
[ADR-0024](docs/decisions/0024-gamepack-and-worldpack-are-additive.md).
Identity migration is recorded in
[ADR-0025](docs/decisions/0025-world-forge-identity-migration.md), with the
[world-project v2-to-v3 guide](docs/MIGRATING_WORLD_PROJECT_V2_TO_V3.md),
[legacy-identity allowlist policy](docs/LEGACY_IDENTITY_ALLOWLIST.md), and
[cutover/rollback runbook](docs/operations/IDENTITY_CUTOVER_AND_ROLLBACK.md).
ADR-0047 adds a private, backend-only durable Director possession authority for
exact Harness tool-approval decisions; see
[ADR-0047](docs/decisions/0047-authenticated-durable-studio-human-decisions.md).
The additive Studio protocol v6 and Electron ceremony in
[ADR-0048](docs/decisions/0048-studio-director-ceremony.md) now let a human
explicitly enroll or unlock the fixed local credential, select and inspect one
exact review, prepare it, approve or deny it, and revoke its current decision.
Python remains the cryptographic and storage authority, Electron main owns the
selected review and compare-and-swap request construction, and the general
renderer exposes only named argument-free operations. This is not civil or
legal identity, secure memory zeroization, automatic Studio execution
hydration, external
whole-store rollback detection, or completion of Slice 4.

[ADR-0049](docs/decisions/0049-durable-studio-agent-harness-approval-binding.md)
adds the first private backend composition between that durable authority and
`AgentExecutionKernel`. The kernel accepts only a weak-registered original
instance of one of its two exact code-owned approval authorities, captures and
rechecks its bound method/function/code identity, and rejects copies,
subclasses, lookalikes, method replacement, or construction-state owner swaps.
It validates and cross-binds
exact immutable reviews, snapshots, and checks, then checks the frozen snapshot
immediately before and again after durable begin. Existing effect-boundary checks and exact-terminal
replay remain in force. Worker, EventLog, receipt, activation/grant, Studio
protocol, generated, and runtime bytes are unchanged; this is not a general
Studio execution service, a standalone receipt proof, or separate-process
kernel isolation.

Admission identities and primitives, Studio provenance consumption, binding
construction/identity/validation, and the Studio provisional/completion
dispatch are captured inside code-owned closures. The kernel constructor does
not dynamically resolve the imported binder and has no separately assignable
live validation hook. Studio construction likewise captures exact frame access
and stores its exact bound-entrypoint factory. Replacing same-named module
globals cannot admit a copied authority, disable a live custody check, or make
enroll/unlock return an attacker-substituted authority.

The weak authority registry is synchronized closure-owned state rather than an
importable mutable mapping. The Studio authority's ordinary constructor is
closed: successful enroll/unlock auditing and transaction completion must issue
and immediately consume one exact one-time construction capability bound to the
Store, credential evidence, event key, and provisional instance before it can
enter Harness custody; equal but nonidentical credential or event-key objects
fail that identity check, and failed registration retires the token. This is
same-process trusted-code hardening against ordinary imported-module rebinding,
not a claim against arbitrary Python reflection in a fully compromised
interpreter.

## Public project

Contributions must follow [AGENTS.md](AGENTS.md) and
[CONTRIBUTING.md](CONTRIBUTING.md). Contract changes must include their schema,
documentation, migration impact, and tests in the same pull request.

Repository documentation and tooling interfaces are maintained in English.
Each world declares its content locales. Each game target separately declares
the locales and UI policy it supports.

### Agent Harness contract foundation

Slice 1B.1 publishes the closed canonical JSON v1 `AgentWorkerActivation` and
`AgentCapabilityGrant` lineage documents. Slice 1B.2 adds `AgentEvent` and
`AgentExecutionReceipt`. Slice 1B.3 adds the final contract-only
`AgentMemoryProjection`. These contracts provide no worker, provider,
execution, Studio, replay, runtime capability, or memory-truth inference.
See [ADR-0030](docs/decisions/0030-agent-harness-contract-foundation.md).

The internal provider-free kernel validates those existing activation/grant
documents and produces deterministic execution records. A separate,
host-supplied private SQLite `AgentEventLog` can durably bind an exact request,
append its bounded event chain, atomically record its terminal receipt, and
audit the canonical bytes after reopen. Ordinary sessions retain a shared
one-byte OS lock; only an exclusive offline recovery session can mark an
interrupted prefix `recovery_required`, and it is never resumed or given a
synthetic receipt. Unsealable private input receives no replay identity, so its
failure receipt cannot be deduplicated on retry. The private SQLite v3 schema,
internal indexes, bounded physical integrity, and startup foreign-key projection
are checked exactly. Exact v1/v2 ordinary stores migrate transactionally; offline
recovery retains exact main/WAL/SHM evidence, validates and applies committed
WAL frames without opening any database pathname, and serves the resulting v1,
v2, or v3 logical image from digest-bound query-only memory. Any rollback-journal
sidecar, including an empty or stale one, fails closed until a reviewed parser
exists. Original crash bytes remain unchanged until an explicit recovery
transition revalidates them and opens the original store. Local evidence proves
the POSIX process fence; Windows lock behavior is seam-tested but not natively
proven by this slice.

The five public v1 contracts remain unchanged and receipts still state
`replay_support: not_claimed`. A private one-shot supervisor defaults to the
fixed, non-production conformance runtime behind an authenticated process gate.
Its runtime identity hashes the actual bootstrap template, and the child
is launched with fixed isolated/no-bytecode flags and exact-validates every
authenticated request before executing an action. Version 1 is Linux-only. Linux
holds worker creation behind a parent acknowledgement, tracks `/proc` state as
well as PID/start time, binds STOP/KILL to retained `pidfd` handles without a
PID-kill fallback, owns scratch cleanup in the parent, and requires clean
control EOF plus bounded process-tree termination before a result is accepted.
Windows and every other host reject `worker_containment_unavailable` before
durable execution begin, broker activation, process creation, or provider
action; no Windows worker backend is present and Windows remains unsupported and
`UNTESTED`. A future reviewed slice requires a custom `CreateProcess` launcher
that acquires containment ownership at creation plus native Windows evidence.
Broker loss remains containment-indeterminate even though the
parent best-effort kills descendants still attributable to known worker
identities. This is not a real provider/model, same-UID filesystem/network
sandbox, vendor telemetry guarantee, Studio job/UI, external MCP boundary,
memory hydration, artifact promotion, deterministic provider replay, or
hosted/native/release claim.
See [ADR-0031](docs/decisions/0031-provider-free-agent-execution-kernel.md) and
[ADR-0032](docs/decisions/0032-private-durable-agent-event-log.md), and
[ADR-0033](docs/decisions/0033-one-shot-isolated-provider-worker.md).

The host-injected provider now exposes the exact existing activation-runtime
binding. The kernel strictly snapshots that binding and the selected bound turn
callable once before any durable or execution authority exists. Ordinary
attribute assignment or later mutation of an adapter's endpoint selector cannot
redirect that kernel to a replacement adapter. This is in-process API hardening,
not protection against `object.__setattr__`, malicious private/module reflection,
or memory corruption in a hostile host. A newly begun activation mismatch
records the existing `failed` / `provider_failed` receipt without activating the
broker, provider, worker, tools, or proposals; cancellation and deadline keep
their precedence. Matching execution binds the receipt to the same runtime, and
an exact terminal duplicate performs no new binding read or worker spawn. This
attestation layer does not select a provider; the later private governance
catalog in ADR-0037 supplies that separate authority. The fixed
conformance runtime uses the activation-compatible private ID
`worldforge_conformance_provider`; its frozen private scalars produce fresh
caller-owned identity documents, and its hash remains pinned to the bootstrap
template built from those same scalars. Public schemas and canonical fixtures
are unchanged. See
[ADR-0034](docs/decisions/0034-exact-provider-runtime-attestation.md).

Concrete tools now require a private per-execution human decision before the
provider boundary can run with them. The host prepares an exact in-memory
review over the execution, runtime, limits, private-input hash, and immutable
eligible tool-descriptor catalog; generation/hash CAS governs approve, deny,
expiry, and revoke. One atomic authority snapshot is fingerprinted before
durable begin, so a decision arriving during begin is not adopted by that
attempt. Reviewer IDs are asserted labels, not authenticated users,
and this slice persists no approval metadata. Approved tools enter the first
turn as bounded summary/hash pairs only; adapters must supply exact summary and
schema metadata. A provider may request full definitions, which retain request
order and become visible and invocable on the next turn; any same-result request
and call fails whole-batch preflight without effects. Hidden, unapproved,
incompatible, and unexposed tools share `tool_not_authorized`. Cancellation, runtime mismatch,
and incurred provider budget evidence retain their defined precedence, and a
revocation can stop a blocked Linux worker through the existing proven-empty
containment boundary. Exact terminal duplicates remain evidence-only even after
revocation, while changed approval or descriptor evidence conflicts. This is
tool approval only: it does not authorize provider/cloud use, cost, data,
credentials, artifacts, or memory promotion. Public Harness bytes remain
unchanged. See
[ADR-0035](docs/decisions/0035-human-approval-and-progressive-tool-exposure.md).

Approved memory projection is now a separate private post-success boundary.
An ephemeral proposal source owns bounded exact JSON values but exposes only
code-owned hashes. A distinct memory authority reviews the exact succeeded
receipt, complete pre-projection event chain/head, candidate snapshot, and fixed
lossless hash-only policy; tool approval cannot authorize it. The deterministic
compiler performs exact hash deduplication and ordering only, never semantic
summarization. The private SQLite schema advances to v2 so one privileged atomic
operation can record the canonical public projection and append exactly one
`memory.projected` event after the receipt. Raw candidate content is absent from
approval, fingerprints, public records, and SQLite. Exact duplicates are
evidence-only; changed lineage or authority conflicts. Memory hydration, scope,
truth promotion, retention/deletion, authenticated review, and durable raw
content remain Studio-owned and unimplemented. Public Harness bytes, worker
protocol, runtime revision, and receipt replay claims remain unchanged. See
[ADR-0036](docs/decisions/0036-approved-hash-only-memory-projection.md).

Provider execution now has a separate private gate before any real adapter can
be added. A code-owned immutable catalog resolves only an exact runtime triple;
it never accepts a command, module, path, factory, SDK, URL, or environment from
an execution request. Its exactly two executable entries are the Linux-only,
network-free, non-production conformance worker and a distinct deterministic
offline probe. An immutable selection binds
the catalog/spec, non-secret configuration, disclosure plan and data classes,
base payload, tool catalog, limits, pricing, and an opaque credential-revision
identity. A distinct in-memory CAS authority reviews four exact facets:
selection, destination/egress/telemetry, disclosed data, and pricing/cost.
The kernel fingerprints one detached decision snapshot before durable begin;
late decisions are not adopted, revocation can stop a blocked Linux worker, and
exact terminal duplicates remain evidence-only after revocation. Missing,
denied, expired, revoked, or stale provider authority collapses publicly to the
existing `provider_failed` code. Secret credential bytes are never accepted.
Artifact factories run once during registry construction and are not retained.
Supervisor construction freezes the selected artifact, specification, protocol
binding, command/environment, process supervisor, and dispatch callable as one
authority; normal reassignment/deletion, later selector mutation, or later
registry/factory rebinding cannot redirect an approved runtime. This does not
claim protection against explicit `object.__setattr__`, malicious private/module
reflection before construction, or hostile-process memory corruption.
Networked descriptors remain unavailable. This adds
no real provider, SDK, network call, credential vault, authenticated Studio
reviewer, Windows support, or production claim. Public Harness v1 bytes remain
unchanged. See
[ADR-0037](docs/decisions/0037-provider-execution-governance.md) and
[ADR-0038](docs/decisions/0038-code-owned-provider-runtime-dispatch.md).

Every code-owned provider worker now binds one private immutable
`deny_all_direct_network` profile. On reviewed Linux `aarch64` and `x86_64`
identities, the fixed launch uses `close_fds=True` and no passed descriptors; a
code-owned launcher runs after that outer exec/descriptor close and performs a
single-threaded census that rejects any socket descriptor before installing
`PR_SET_NO_NEW_PRIVS` and the exact seccomp-BPF filter. Only then does it exec
the fixed worker bootstrap. The filter rejects all x32 syscall aliases on
x86_64, direct IPv4/IPv6/Unix socket
operations, descriptor acquisition through `pidfd`, SCM_RIGHTS receive paths,
`io_uring` and BPF entry points, and namespace-changing calls. Ordinary
fork/exec and anonymous-pipe IPC remain available, and descendants inherit the
filter. Generic `read`/`write` are intentionally available for that pipe IPC;
the invariant therefore depends on both the clean-descriptor launch proof and
the acquisition-denial filter, not seccomp alone. The two offline runtime IDs
remain fixed, while their current exact bootstrap bytes, private specifications,
and catalog bind the profile hash. Unsupported systems and setup failures fail closed
through existing private boundaries. This is not a complete OS network sandbox,
host firewall, filesystem sandbox, trusted-parent gateway, real-provider, or
Windows claim. Public Agent Harness bytes and EventLog records remain unchanged. See
[ADR-0039](docs/decisions/0039-deny-all-provider-worker-egress.md).

The deterministic probe can now prove one governed fixed ordered local plan
without weakening that worker boundary. Its revision-6 bootstrap submits one
authenticated semantic request over stdin/stdout to the existing broker. The
main parent alone opens two fresh nonblocking sockets sequentially to the exact
numeric IPv4 or IPv6 loopback origin: a bodyless GET followed by a canonical
JSON POST to `/worldforge/v1/ordered-loopback-probe`. Each socket is closed
before the next step or relay. Side-band v2 returns exactly two authenticated
ordered records under a cumulative HMAC chain; the worker final binds the
terminal chain before result acceptance after the worker domain is empty. One
absolute deadline is shared, and the private turn deadline can shorten the
two-second plan deadline. The exact origin, plan/policy, ADR-0039 enforcement,
code-owned no-telemetry branch, catalog, selection, and provider approval hashes
remain aligned. There is no DNS, proxy, redirect, retry, reconnect, socket
inheritance, real provider, credential, vendor telemetry claim, or production
eligibility. Once any send syscall is attempted, every later uncertainty leaves
the durable prefix open for offline recovery. See
[ADR-0040](docs/decisions/0040-parent-owned-exact-origin-loopback-gateway.md)
and [ADR-0043](docs/decisions/0043-fixed-ordered-loopback-operation-plan.md).
The frozen plan document hashes the complete deadline, socket lifecycle,
request-header generation, HTTP response/parser, ordinary-JSON, aggregate-bound,
and first-send-latch policy; valid JSON `null` remains distinct from an internal
missing-response sentinel.
Its exact monotonic anchor is captured after supervisor authority validation and
turn-lock acquisition but before scratch or process setup, so setup delay consumes
the plan budget and loopback entry cannot reset it.

The deterministic probe can now run that exact gateway plan against one
code-owned neutral synthetic local service. Importing `worldforge.agent_harness`
does not resolve Linux-only symbols: an exact platform/runtime preflight runs
before policy, catalog, journal, bind, spawn, or provider effects, and a
lock-guarded loader then freezes the required Linux CPython 3.12 authority.
Unsupported hosts reject instead of creating synthetic provider state.

For each genuinely new supported turn, the parent retains a fresh one-use
`127.0.0.1:0` listener lease. The single-threaded broker blocks every catchable
launch signal before checking that no sibling thread, trace, or profile callback
exists. It emits the normal `subprocess.Popen` audit event, revalidates the exact
frozen authority after that callback, constructs the fixed pre-exec custody
closure only then, and calls the captured low-level `subprocess._fork_exec`.
The child installs `prctl(PR_SET_PDEATHSIG, SIGKILL)`, immediately verifies the
exact broker PPID, restores the broker's prior signal mask, and execs the pinned
non-privilege-changing executable. The broker opens a pidfd immediately and uses
pidfd-based wait, signal, and reap operations with EINTR-safe, idempotent cleanup.

Before any configuration or HMAC secret is released, the fixed bootstrap and
parent jointly prove the exact parent-death signal, PID/PPID/start identity,
`SigBlk`, executable and bytes, cmdline, root, scratch-directory cwd,
four-key environment, and complete FD roles. An authenticated PID/start handoff
then lets the main parent retain its own pidfd before the broker opens the
configuration gate. Canonical readiness remains bound to the exact
lease/recipe/policy identities, and listener ownership is rechecked at every
gateway boundary. Listener-inode scanning is observation-only absence evidence:
it never adds a process to a kill set or grants signal authority. Cleanup signals
only exactly retained PID/start/pidfd identities and requires a fixed-point
domain-empty plus listener-absent proof before return; broker loss before
fencing remains indeterminate even when kernel custody removes the service.
There is no restart, retry, attach, reuse, or recovery path.

This capability has native evidence only on Linux `aarch64`, CPython `3.12.3`,
`/usr/bin/python3`. Simulated `win32` and `darwin` clean-import tests are not
native Windows or macOS execution. Python 3.11, x86_64, actual Windows/macOS,
hosted CI, full test discovery, real providers/models/APIs, credentials, vendor
telemetry guarantees, Studio surface, and production readiness remain untested
or pending and are not claimed. See
[ADR-0045](docs/decisions/0045-code-owned-local-service-lease-attestation.md).

Private provider turns use the version-2 authenticated correlated transcript
instead of arbitrary history. Every accepted turn records one transient
assistant item first, including ordered calls with mandatory provider-neutral
IDs, then one exact correlated tool-result item per successful call. IDs are
unique across the execution; missing, reused, orphaned, reordered, or mismatched
correlation fails before batch tool effects, and a completed result cannot also
request tools. Identical tool and argument requests remain valid when their
neutral IDs differ. Each assistant item is bounded to 128 calls in host and
self-contained worker validation. The transcript is sealed, cumulatively
bounded to 64 KiB, and absent from public receipts, events, EventLog/SQLite,
and stderr. Provider protocol v3 adds separately authenticated usage evidence.
The conformance runtime is revision 4 and the deterministic probe is revision 6,
with both existing runtime IDs and exactly two catalog entries retained. The
loopback side-band is version 2.

Input, output, cached-input, and cost evidence use closed
observed/derived/unavailable states and source kinds; derived tokens bind an
explicit code-owned measurement-policy identity. Valid authenticated usage is
durably accounted even when a sibling result field is malformed, while invalid
outer authentication/runtime/hash evidence is never salvaged. Private EventLog
v3 atomically stores one canonical sanitized usage-accounting document with
every terminal receipt and synthesizes conservative legacy accounting during
v1/v2 migration or detached reads.

Public receipt token and cost fields are recognized/accounted ledger totals,
not measurement truth. Cached zero can mean no recognized cache claim, not
observed absence of caching. Null cost/currency means no recognized cost claim,
not zero cost. Worker-originated money remains rejected. The parent now owns one
closed non-production `XTS` pricing policy for the deterministic probe only:
integer execution-total ceiling rounding derives `2 XTS` minor units for its
default one-input/one-output turn, even though cache evidence is unavailable,
because its cached and uncached rates are exactly equal. Both reserved runtime
identities are exact: conformance must match its canonical revision, bootstrap
content hash, and usage-policy hash and remains unpriced; the probe must match
its own canonical triple, usage policy, policy, and currency. A priced selection
may omit a cost ceiling; when present, the ceiling currency must be exact `XTS`.
Live catalog, resolution, and accounting-lineage authority is held only in
construction-owned, identity-checked weak-reference registries that also retain
the exact registered hashes; no transferable proof is embedded in
caller-visible values. Exact weak-reference callbacks retire only their own
registration, so collected executions release authority without allowing a
stale callback to remove a newer same-ID registration.
The sole root factory builds the closed catalog itself and accepts no caller
catalog or specification. Copies, subclasses, `object.__new__` clones,
owner-retargeted internals, coherent mutations, and arbitrary lineage hashes
cannot mint live authority. This is a trusted-same-process/private-module
boundary, not resistance to monkeypatching those private registries. A private
begin-time lineage record retains the validated runtime-specification and full
selection hashes. Priced execution uses a private journal extension to store it;
unpriced conformance retains the baseline public `ExecutionJournal` call, while
a legacy journal without that private extension rejects pricing before any
provider turn or action. The unkeyed request commitment is a semantic
consistency linkage, not an independent or authenticated anchor: it detects
individual and partial lineage drift against the accepted request row. Durable
replay reconstructs that stored semantic linkage without granting live
authority, and every priced finalize/replay resolves the exact code-owned probe
runtime, usage policy, pricing policy, and `XTS` currency before checking
accounting. As specified by
[ADR-0032](docs/decisions/0032-private-durable-agent-event-log.md), a coherent
same-UID rewrite of all affected projections and hashes remains outside this
slice. Exact
terminal duplicates perform no new provider turn or live pricing transition,
and legacy rows are never repriced.
This is synthetic ledger evidence, not a vendor price, invoice, billing or
freshness claim. See
[ADR-0041](docs/decisions/0041-private-correlated-provider-turn-transcript.md),
[ADR-0042](docs/decisions/0042-truthful-private-provider-usage-provenance.md),
and [ADR-0044](docs/decisions/0044-parent-owned-exact-synthetic-pricing.md).

### Corrected observed Ollama evidence v2 — foundation, controller, and backend authorization

ADR-0050 now makes the ADR-0046 disposition explicit and mechanically
verifiable without editing its historical bytes. The pure
`worldforge.provider_evidence.ollama_v2` package pins ADR-0046's raw SHA-256 and
isolates its exact ordered 86-row vocabulary table, rather than treating a
forbidden alias in surrounding prose as a registry entry. It validates two
closed canonical documents: v1 is permanently unavailable with no
migration/conversion/promotion path, while the v2 policy requires a dedicated
`worldforge-ollama-evidence` principal, copied sealed release/model custody,
installed systemd socket activation with matching
`FileDescriptorName=ollama-http` and `StandardInput=fd:ollama-http`, exact
cloud-off numeric-loopback/no-proxy constraints, and a CPU-only no-accelerator
boundary.

The second boundary adds a deterministic private controller core. Frozen exact
contracts bind the policy vector, fixed UID/GID, bounded sealed tree manifests,
independent UID/GID-owner censuses, principal/unit/host observations, closed
effects, one-use authorizations, operation-specific ownership tokens,
operations, and reverse rollback. A separate exact-schema SQLite store uses
`BEGIN IMMEDIATE`, generation/sequence/head/state CAS, canonical documents,
event hash chaining, unique authorization/effect-attempt identities, and one
exclusive fixed-host-scope lease. Every mutation reports which caller
atomically committed it, and semantic reopen/replay requires an exact bijection
between transition events, authorization outcomes, attempts, host
projections, and ownership. Closed captured ports expose only
`inspect`/`observe`, `consume`/`resolve`, and one named method per effect; there
is no shell, argv, generic command, or generic RPC surface. Every possible
effect verifies the complete host projection before and after dispatch. Drift
in any prior or cleaned resource fails closed before another authorization or
effect, and rollback is explicit. The scope lease is released only by exact
`rolled_back_clean` proof.

StudioStore schema v8 adds a backend-only authenticated plan-mandate and
terminal-settlement domain without changing Studio protocol v6 or Electron. It
reuses the exact unlocked `director_local` credential, verifier evidence,
private Store connection and `RLock`, event key, and lifecycle epoch. One finite
canonical mandate binds an exact remaining apply or rollback scope, plan
documents, starting controller snapshot, ownership/policy/interpreter hashes,
ordered effect IDs and full effect hashes, derived impact, prohibited egress,
and pricing as not applicable. The impact binds the controller's exact
document/tree/entry/effect ceilings and the selected manifests' actual counts
and sizes.

The schema-v8 outcome ledger records exactly one `consumed` or `rejected`
settlement for a mandate slot and controller authorization. Every consumed
outcome has one exact consumption-projection row; rejected outcomes have none.
The authenticated event chain includes `rejected`, while revoked and expired
claimed requests settle durably instead of remaining ambiguous. Primary
v7-to-v8 migration rebuilds the domain atomically, backfills every legacy
consumption into that ledger, and verifies the exact bijection before commit;
secondary attachment requires v8 and never migrates.

Its closed controller port has only `consume` and `resolve`, returns the
canonical `AuthorizationOutcome` (`AuthorizationConsumption` or
`AuthorizationRejection`), durably settles one nonrefundable slot per exact
effect, never lets apply imply rollback, and never adopts a compatible or latest
approval.
Binding requires the exact already-open `OllamaV2ControllerStore` instance and
operation identity; Studio opens no controller connection. The port captures
that store's exact read targets and private custody objects. On every bind it
derives the mandate slot from the phase cursor relative to the mandate's
starting cursor, not from a Studio counter. It accepts only the exact current
phase state: pending, authorization-pending, authorization-claimed,
authorization-consumed, or dispatching. Every completed prior slot must have
one contiguous five-transition Controller cycle—pending authorization, claim,
consumption, dispatch, and observation—with exact request, attempt,
consumption, event, snapshot, and matching Studio-outcome evidence. The current
slot must have the exact corresponding prefix. Controller attachment rereads
and compares that whole proof before enabling the port.

`consume` accepts only the exact currently claimed request document and hash,
not a counter or nonzero-head heuristic. The claimed controller state is a
monotonic settlement fence: it stays claimed until an exact durable consumed or
rejected outcome is resolved, and live generic recovery cannot clear it.
Historical ControllerStore recovery events from the earlier format remain
readable. No host preflight observation or effect occurs before settlement; a
rejection moves the controller directly to `recovery_required`. `resolve`
remains read-only and works only for that exact durable lineage. Restarted
controllers continue safely from pending, authorization-pending, claimed, or
consumed; an exception-reconciled non-owner stops at the exact durable
post-state. Dispatching resumes observation only and never redispatches the
effect.

The evidence now includes both graceful same-process Store reopen tests and a
fresh OS-process SQLite saga gate. The latter uses eight APPLY/ROLLBACK crash
paths plus denied, with independent crash, recovery, and audit interpreter
processes. It brackets the boundaries immediately before Studio `COMMIT`,
committed-before-return, controller claim commit, and controller outcome
acknowledgement commit, proving one terminal settlement and at-most-once
test-local effect across reopen. Two additional full fresh-process ladders each
walk all nine APPLY or ROLLBACK effects through the five resumable states. Each
dispatch child exits after one test-local effect marker, and a new child resumes
from dispatching by observation only. They finish at `prepared_unverified` and
`rolled_back_clean` with nine exact Controller/Studio outcomes and no duplicate
effect. These gates do not simulate interruption inside SQLite `COMMIT`, power
loss, a native Ollama process, systemd, host mutation, or inference.
Revoke compares the exact consumed-slot cursor, lock invalidation shares the
private authority `RLock`, and independent connections still produce one slot
winner.
Authenticated replay validates exact built-in JSON and SQLite scalar types
before semantic equality, so rehashed/re-MACed booleans or integral floats
cannot impersonate integer generations, cursors, attempts, sequences, expiry,
or versions. Exact terminal apply and zero-effect rollback scopes are rejected
without minting authority.

This is functional **non-native transaction logic** only. Apply terminates at
`prepared_unverified`, never at observed/available/PASS/production-ready. Stage
A foundation, B controller core, and C backend Studio authorization are
complete. The D concrete host interpreter/broker, E Studio protocol/Electron/UI
ceremony, F host preparation, and G native evidence and real inference are
absent.
Status remains `unavailable` and `production_eligible: false`; Ollama is not in
the provider catalog and no test-local fake is reported as provider or systemd
PASS evidence. The existing two synthetic runtime identities and protected
Harness/public bytes remain exact.
See
[ADR-0050](docs/decisions/0050-studio-director-governed-ollama-evidence-v2.md)
and the strict-TDD evidence for the
[foundation](docs/evidence/ollama-observed-evidence-v2-contract-tdd.md) and
[controller core](docs/evidence/ollama-observed-evidence-v2-controller-tdd.md),
plus the
[Studio backend authorization](docs/evidence/ollama-observed-evidence-v2-studio-authorization-tdd.md).

ADR-0050-D2.2a adds two Linux/aarch64 probe-specific C17 executables and their
closed `NEGOTIATE -> UNAVAILABLE_TERMINAL -> EOF` codec. This is a real,
statically attested build artifact whose PIE executables dynamically depend on
host libc; it is not the future host interpreter/broker:
`codec_implementation_state: built`, `effect_interpreter_state: absent`,
`availability: unavailable`, and `production_eligible: false`. The probes can
express no effect or provider operation and reject zero-length seqpacket records
as non-EOF. The `NEGOTIATE` body advertises message type 1 for negotiation and
message type 2 for the unavailable terminal response. The builder retains every
entry in the exact ten-file source census,
materializes both roots only from retained bytes, and rechecks named source
identity before publication. Build-profile parsing is bound to an immutable
exact field vector rather than lazy factory state. The sdist gate independently
owns the ten exact source path/role pairs and validates every nested source-lock
entry before matching archive bytes. Authoritative publication accepts only
direct source-file execution of the D2.2a native builder. It reads, compiles,
and executes the declared contract `.py` through a source-only loader that does
not consult cached bytecode; imported and `-m` entry modes cannot publish.
Both declared source entries must match the running source bytes before any
tool query, and active identities are rechecked before publication. This is
local source-to-active-code correlation, not Python interpreter,
standard-library, in-memory-code, or independent source custody. Its exact
126-entry toolchain census includes the five executed tool binaries, the
driver-reported `lto-wrapper`, the linker-opened `liblto_plugin.so`,
`/etc/ld.so.cache`, and their complete declared direct/recursive AArch64 ELF
runtime-library graph. It also locks the `libgcc_s.so` and `libc.so` GNU ld
scripts and all of their resolved regular inputs, including
`libc_nonshared.a`. Every authoritative link captures GCC `-v` and GNU ld
`--trace` diagnostics. The immutable build profile pins the normalized complete
diagnostic transcript; every ordered stdout/stderr line and every traced path
must match, so omitted, extra, malformed, localized, duplicated, or reordered
output fails before the ELF can enter an archive. The system/toolchain trace
path spellings are retained byte-for-byte, including GCC's legitimate
`../../../` segments; only exact generated output, object, and resolution-file
paths are substituted. Symlink and lexical aliases such as `/./`, alternate
`/../`, or duplicate slashes fail even when they resolve to the same bytes.
The GCC driver is
descriptor-bound and all locked tool inputs receive pre/post path and byte
checks, but GCC subtools cannot all be descriptor-forced; independent source or
installation custody, kernel/locale closure, and malicious-root or coherent
same-principal substitution resistance are not claimed. See the
[bounded evidence record](docs/evidence/ollama-v2-native-static-codec-d22a.md).

Slice 2B adds a pure deterministic evaluator and explicit-input, atomic
no-replace CLI for the closed recorded-result plan, observation, and report
documents. They evaluate supplied evidence only; they do not execute a
benchmark, query an index, contact an MCP/provider, or independently authorize
adoption. The committed fixtures are synthetic and truthfully `not_evaluable`;
no actual A/B/C benchmark has been run and no candidate has been adopted. See
[`CODEBASE_MEMORY_BENCHMARK.md`](docs/CODEBASE_MEMORY_BENCHMARK.md).
