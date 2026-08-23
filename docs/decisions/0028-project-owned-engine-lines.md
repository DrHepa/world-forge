# ADR-0028: Plan project-owned Engine Lines beside immutable runtime snapshots

- Status: accepted as planned Slice 1 foundation
- Date: 2026-08-23

## Context

An external game needs editable engine code without mutating its parent game,
its imported immutable artifacts, or an applicable `src/isoworld/` snapshot.
The existing game scaffold has no Engine Line implementation, and its current
runtime/platform boundaries remain authoritative.

## Decision

The Forge-independent `gamepack_runtime` kernel is already implemented as the
neutral runtime boundary. Slice 5 plans an additive formal SDK/ABI role and
evolution, not the kernel's future existence. Each Slice 5 materialized
external game will contain:

```text
src/isoworld/  immutable runtime snapshot where applicable
src/engine/    editable engine owned by that game
src/game/      game-specific rules and content
engine.lock.json exact immutable EngineRelease identity consumed by that game
```

The planned vocabulary is `EngineProfile`, `EngineLine`, `EngineRelease`,
`EnginePackage`, `EngineLock`, `EngineCompatibilityReport`,
`EngineMigrationPlan`, and `EngineMigrationReceipt`. An Engine Line is owned
by its game. Releases and packages are immutable; a lock identifies the exact
release consumed by a game and compatibility/migration evidence records API,
ABI, save, asset, platform, and invalidation effects.

A new related game or sequel imports one exact parent `EngineRelease`, creates
a new derived line/revision with `derived_from`, and materializes an editable
copy in its own `src/engine/`. It never modifies the parent game, parent engine,
or parent build. Only within editable `src/engine/` may declared code under
`src/engine/adapters/` import pyray; pyray is an adapter boundary, not the
engine definition. The immutable legacy `src/isoworld/` snapshot retains its
published compatibility imports.

A future development-only `GameControlPort` may expose bounded step, pause,
reset, semantic input, allowlisted observation, frame capture, metrics, saves,
and replays. It must be disabled or absent in releases and never expose shell,
arbitrary Python, or runtime AI.

The Slice 5 external layout and formal SDK/ABI evolution are explicitly **not
implemented in the current scaffold**. This ADR changes neither its existing
layout nor current runtime claims until Slice 5.

## Consequences

- Reuse can preserve immutable parent releases while allowing project-local
  engine evolution.
- Engine changes gain an explicit compatibility and migration vocabulary.
- Existing `src/isoworld` immutability and `src/game` ownership remain intact.

## Rejected alternatives

### Edit a parent game's engine for a sequel

Rejected because it rewrites a released game's provenance and compatibility.

### Make pyray the common engine ABI

Rejected because pyray is a declared platform adapter, not a generic engine
contract.
