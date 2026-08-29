# ADR-001: Normalize Security Events

## Status

Accepted

## Context

MiniSOC will ingest security telemetry from multiple heterogeneous
sources including Linux authentication logs, Windows Event Logs,
firewall logs and network telemetry.

Each source uses different field names and formats.

## Decision

All incoming telemetry will be converted into a common EventSchema
before being passed to the Detection Engine.

## Consequences

### Positive

- Detection rules become source-independent.
- Detection logic does not need to understand every log format.
- New telemetry sources can be added without rewriting detection rules.
- Testing becomes easier because detection rules consume a predictable object.

### Negative

- Each new telemetry source requires a parser/normalizer.
- Some source-specific information may require extension fields.