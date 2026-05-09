# Resource Bounds v1 Specification

## Summary

Resource Bounds v1 provides deterministic hard caps for canonical input structures before they
are hashed or evaluated as authority-bearing evidence.

## Goals

- Bound string length, metadata depth, mapping width, sequence length, total node count,
  canonical JSON byte length, decision trace stage count, and scenario suite count.
- Reject non-finite floats and unsupported object values.
- Provide custom bounds for targeted adversarial tests while keeping defaults high enough for
  validation-layer diagnostics to remain observable.

## Non-Goals

- No memory profiler or runtime resource scheduler.
- No filesystem, process, network, hardware, middleware, or environment inspection.
- No replacement for validation-layer semantic limits.

## Default Bounds

- `max_string_length = 100000`
- `max_metadata_depth = 64`
- `max_mapping_width = 1024`
- `max_sequence_length = 2048`
- `max_total_nodes = 65536`
- `max_canonical_json_bytes = 1048576`
- `max_trace_stage_count = 32`
- `max_scenario_count = 256`

These defaults are deterministic safety rails. Narrower subsystem validation rules may reject
inputs first and produce domain-specific violations.