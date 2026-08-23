# ADR-0027: Define Virtual Studio governance before Team Mode

- Status: accepted as planned Slice 1 foundation
- Date: 2026-08-23

## Context

Future multi-worker authoring needs explicit accountability. A roster of model
calls cannot safely stand in for project ownership, independent review, human
approval, or genuine diversity of judgment.

## Decision

Virtual Studio uses typed governance vocabulary:
`DepartmentDefinition`, `WorkerProfile`, `StudioRoster`, `WorkOrder`,
`TaskLease`, `Handoff`, `DefectRecord`, `ConsultantEngagement`,
`CompetencyAttestation`, `UserDecision`, `TeamSession`,
`ParticipantBinding`, and `DeliberationReport`.

V1 has exactly one human director. Professional profiles are stable, but every
work order receives fresh task context rather than inheriting an unbounded
conversation. A worker may not directly modify property owned by another
worker. Defects route to one owner for repair; independent QA verifies the
repair and does not silently become the owner.

The system may propose consultants, but the user approves their version, cost,
data exposure, and permissions before activation. Team Mode requires exactly
three distinct model lineages. Multiple roles using one lineage do not count as
independent consensus. If three distinct lineages are unavailable, the Studio
displays a visible degraded mode and does not claim consensus.

This ADR is vocabulary and governance only. It creates no Team Mode service,
roster, worker execution, consultant purchase, Studio protocol, or UI.

## Consequences

- Responsibility, repair, QA, and user decisions can be recorded separately.
- Stable roles do not accumulate accidental ambient task authority.
- A degraded diversity condition is reviewable rather than hidden behind a
  numerical vote.

## Rejected alternatives

### Let agents hire or approve themselves

Rejected because costs, data access, and authority require a human decision.

### Count repeated calls to one model as independent review

Rejected because role labels do not establish independent model lineage.
