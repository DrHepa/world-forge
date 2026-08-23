# ADR-0029: Plan a three-surface Tool Center around capabilities, workflows, and runs

- Status: accepted as planned Slice 1 foundation
- Date: 2026-08-23

## Context

Authoring tools, provider adapters, workflows, durable execution, output QA,
and asset promotion require separate authority. A generic frontend, arbitrary
node graph, or undifferentiated tool catalog would collapse those boundaries.

## Decision

The future Tool Center has exactly three primary surfaces:

1. `Capabilities`
2. `Workflows`
3. `Runs`

Setup/Health is an auxiliary drawer. Node Catalog appears within Workflows.
Outputs/QA appears in an individual run and in `Creation > Assets`. Full
third-party applications open externally rather than being embedded as arbitrary
webviews or frontend surfaces.

The planned common vocabulary is `ToolInstallation`, `ToolHealthSnapshot`,
`CapabilityCatalogSnapshot`, `WorkflowRevision`, `WorkflowDependencyReport`,
`ToolRun`, `ToolRunReceipt`, and `ToolOutputCandidate`. World Forge owns the
logical workflow, durable queue, evidence, and asset-promotion boundary.
Modly and ComfyUI retain provider-specific adapters and contracts.

The workflow editor accepts only approved schema-described nodes compatible
with headless execution. A logical DAG is not a permission to execute arbitrary
frontend code, widgets, endpoints, commands, or RPC. Incompatible workflows
open in their owning external application.

Slice 1 supplies no Tool Center UI and no discovery, installation, update,
execution, download, or provider action.

## Consequences

- Tool presence, health, workflow validity, execution, outputs, QA, and asset
  promotion can remain independently evidenced.
- Provider-specific behavior remains behind adapters rather than expanding the
  shared logical contract.
- Future UI scope stays bounded to the three named primary surfaces.

## Rejected alternatives

### Build a general tool marketplace in Slice 1

Rejected because discovery and installation are privileged mutation surfaces,
not foundation vocabulary.

### Accept arbitrary frontend workflow graphs

Rejected because UI widgets and arbitrary code cannot establish a deterministic
headless workflow contract.
