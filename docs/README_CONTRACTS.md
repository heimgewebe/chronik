# Contracts and Schemas

This directory contains schemas and documentation defining the interfaces (contracts) for the system.

## Source of Truth

**The Canonical Source of Truth (SSOT) is the `metarepo`.**

*   Schemas found in `docs/*.schema.json` within this repository are **mirrors** intended for local development, validation, and testing logic.
*   While they strive to be up-to-date, they should not be treated as the authoritative definition.
*   The `$id` fields in these local mirrors are kept canonical (pointing to `heimgewebe/contracts/...`) to ensure that validation logic behaves consistently with production environments.

## Event Contracts

See `event-contracts.md` for a detailed list of supported events and their requirements.
