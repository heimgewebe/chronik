# Contracts and API Semantics

This directory contains local documentation and notes.

**Canonical Contracts** are located in the `heimgewebe/metarepo` repository under `contracts/`.

This repository does **not** contain canonical schema definitions. Any schemas found here are strictly for local development or documentation purposes and should not be treated as the Single Source of Truth (SSOT).

## API Contracts

- `chronik.event.batch.v1`: Defines the response format for `GET /v1/events`.
  See: `https://github.com/heimgewebe/metarepo/tree/main/contracts/chronik/event.batch.v1.schema.json`

## Domain Semantics

Chronik stores events in domains. While the API accepts arbitrary valid domain strings (sanitized to alphanumeric, dots, dashes), consumers should adhere to the following conventions to ensure semantic stability:

- **Format**: `dotted.notation` (e.g., `knowledge.observatory`, `heimgeist.insight`).
- **Case**: Always lowercase.
- **Mapping**: Domains typically map to specific event types or aggregate streams defined in `metarepo/contracts/consumers.yaml`.
- **Cursor**: The `cursor` returned by `/v1/events` is a **Byte Offset**. Clients must persist this integer to resume consumption reliably using the `heimlern.ingest.state.v1` contract.
