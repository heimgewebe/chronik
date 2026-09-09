"""Typed validation for Chronik's persisted coding-memory state boundaries.

This module is intentionally structural only. Callers retain semantic checks such as
repository paths, schema constants, digests, timestamps, and cross-file identities.
Keeping structural narrowing here makes persisted JSON stop being ``Any`` immediately
after parsing without creating a second source of runtime authority.
"""

from __future__ import annotations

from typing import TypedDict


class InventoryFingerprint(TypedDict):
    count: int
    sha256: str


class FileIdentity(TypedDict):
    device: int
    inode: int
    mode: int
    links: int
    uid: int
    size: int
    mtime_ns: int
    ctime_ns: int


class SourceInventoryIdentity(TypedDict):
    artifacts: InventoryFingerprint
    source_dir: FileIdentity
    bundle_dir: FileIdentity


class StorageCheckpointIdentity(TypedDict):
    schema_version: int
    identity_key: str
    ledger: FileIdentity
    identity_index: FileIdentity


class DeltaCandidateIdentity(TypedDict):
    source_inventory: SourceInventoryIdentity
    source_index_identity: FileIdentity
    delta_index_identity: FileIdentity
    delta_overlay_identity: FileIdentity


class SteadyCheckpointIdentityWithReceipts(TypedDict):
    source_inventory: SourceInventoryIdentity
    receipt_inventory: InventoryFingerprint
    source_index_identity: FileIdentity
    delta_index_identity: FileIdentity
    delta_overlay_identity: FileIdentity
    target_identity: StorageCheckpointIdentity


class SteadyCheckpointIdentityDeferredReceipts(TypedDict):
    source_inventory: SourceInventoryIdentity
    receipt_inventory_deferred: bool
    source_index_identity: FileIdentity
    delta_index_identity: FileIdentity
    delta_overlay_identity: FileIdentity
    target_identity: StorageCheckpointIdentity


SteadyCheckpointIdentity = (
    SteadyCheckpointIdentityWithReceipts | SteadyCheckpointIdentityDeferredReceipts
)


class SteadySummary(TypedDict):
    files_seen: int
    loose_files_seen: int
    bundle_manifests_seen: int
    bundles_valid: int
    bundled_sources_seen: int
    sources_seen_total: int
    sources_after_deduplication: int
    orphan_bundles: int
    files_imported_or_confirmed: int
    files_unchanged: int
    receipts_written: int
    receipts_reused: int
    receipts_deferred: int
    loose_sources_imported_or_confirmed: int
    bundled_sources_imported_or_confirmed: int
    events_imported: int
    events_skipped_existing: int
    target_scans: int
    target_records_scanned: int
    identity_index_mode: str
    identity_index_full_rebuild: bool
    identity_index_entries_after: int
    source_index_mode: str
    source_index_file_bytes: int
    sources_reused: int
    sources_revalidated: int
    sources_changed: int
    sources_added: int
    sources_removed: int
    source_bytes_read: int
    source_bytes_hashed: int
    source_events_validated: int


class SteadyCheckpointDocument(TypedDict):
    schema_version: str
    source_dir: str
    selection_contract: list[str]
    identity: SteadyCheckpointIdentity
    summary: SteadySummary
    recorded_at: str
    historical_only: bool
    does_not_establish: list[str]
    checkpoint_sha256: str


class DeltaSourceRecord(TypedDict):
    source_path: str
    source_sha256: str
    source_bytes: int
    event_count: int
    source_identity: object


class ValidatedDeltaSourceRecord(DeltaSourceRecord):
    _identity: tuple[int, ...]


class DeltaBundleRecord(TypedDict):
    manifest_path: str
    manifest_identity: object
    bundle_path: str
    bundle_identity: object
    source_paths: list[str]
    source_count: int
    event_count: int


class ValidatedDeltaBundleRecord(DeltaBundleRecord):
    _manifest_identity: tuple[int, ...]
    _bundle_identity: tuple[int, ...]


class DeltaIndexDocument(TypedDict):
    schema_version: str
    source_dir: str
    selection_contract: list[str]
    loose_sources: list[DeltaSourceRecord]
    bundles: list[DeltaBundleRecord]
    source_count: int
    event_count: int
    recorded_at: str
    historical_only: bool
    does_not_establish: list[str]
    index_sha256: str


class LoadedDeltaIndexDocument(DeltaIndexDocument):
    _loose_sources: list[ValidatedDeltaSourceRecord]
    _bundles: list[ValidatedDeltaBundleRecord]


class DeltaOverlayDocument(TypedDict):
    schema_version: str
    source_dir: str
    base_index_sha256: str
    records: list[DeltaSourceRecord]
    record_count: int
    recorded_at: str
    historical_only: bool
    does_not_establish: list[str]
    overlay_sha256: str


class LoadedDeltaOverlayDocument(DeltaOverlayDocument):
    _records: list[ValidatedDeltaSourceRecord]


def _exact_object(
    value: object, expected: set[str], *, label: str
) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"invalid {label} object")
    document = {key: item for key, item in value.items()}
    if set(document) != expected:
        raise ValueError(f"invalid {label} fields")
    return document


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"invalid {label}")
    return value


def _integer(value: object, *, label: str) -> int:
    if type(value) is not int:
        raise ValueError(f"invalid {label}")
    return value


def _boolean(value: object, *, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"invalid {label}")
    return value


def _object(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"invalid {label}")
    return {key: item for key, item in value.items()}


def _objects(value: object, *, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"invalid {label}")
    return list(value)


def _strings(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"invalid {label}")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"invalid {label}")
        result.append(item)
    return result


def _parse_inventory_fingerprint(value: object, *, label: str) -> InventoryFingerprint:
    document = _exact_object(value, {"count", "sha256"}, label=label)
    return {
        "count": _integer(document["count"], label=f"{label} count"),
        "sha256": _string(document["sha256"], label=f"{label} digest"),
    }


def _parse_file_identity(value: object, *, label: str) -> FileIdentity:
    document = _exact_object(
        value,
        {"device", "inode", "mode", "links", "uid", "size", "mtime_ns", "ctime_ns"},
        label=label,
    )
    return {
        "device": _integer(document["device"], label=f"{label} device"),
        "inode": _integer(document["inode"], label=f"{label} inode"),
        "mode": _integer(document["mode"], label=f"{label} mode"),
        "links": _integer(document["links"], label=f"{label} links"),
        "uid": _integer(document["uid"], label=f"{label} uid"),
        "size": _integer(document["size"], label=f"{label} size"),
        "mtime_ns": _integer(document["mtime_ns"], label=f"{label} mtime"),
        "ctime_ns": _integer(document["ctime_ns"], label=f"{label} ctime"),
    }


def _parse_source_inventory_identity(value: object) -> SourceInventoryIdentity:
    document = _exact_object(
        value, {"artifacts", "source_dir", "bundle_dir"}, label="steady source inventory"
    )
    return {
        "artifacts": _parse_inventory_fingerprint(
            document["artifacts"], label="steady source artifact inventory"
        ),
        "source_dir": _parse_file_identity(
            document["source_dir"], label="steady source directory identity"
        ),
        "bundle_dir": _parse_file_identity(
            document["bundle_dir"], label="steady bundle directory identity"
        ),
    }


def _parse_storage_checkpoint_identity(value: object) -> StorageCheckpointIdentity:
    document = _exact_object(
        value,
        {"schema_version", "identity_key", "ledger", "identity_index"},
        label="steady storage checkpoint identity",
    )
    return {
        "schema_version": _integer(
            document["schema_version"], label="steady storage checkpoint schema"
        ),
        "identity_key": _string(
            document["identity_key"], label="steady storage checkpoint identity key"
        ),
        "ledger": _parse_file_identity(
            document["ledger"], label="steady ledger identity"
        ),
        "identity_index": _parse_file_identity(
            document["identity_index"], label="steady ledger index identity"
        ),
    }


def _parse_steady_checkpoint_identity(value: object) -> SteadyCheckpointIdentity:
    document = _object(value, label="steady checkpoint identity")
    shared = {
        "source_inventory",
        "source_index_identity",
        "delta_index_identity",
        "delta_overlay_identity",
        "target_identity",
    }
    keys = set(document)
    if keys == shared | {"receipt_inventory"}:
        result: SteadyCheckpointIdentityWithReceipts = {
            "source_inventory": _parse_source_inventory_identity(
                document["source_inventory"]
            ),
            "receipt_inventory": _parse_inventory_fingerprint(
                document["receipt_inventory"], label="steady receipt inventory"
            ),
            "source_index_identity": _parse_file_identity(
                document["source_index_identity"], label="steady source index identity"
            ),
            "delta_index_identity": _parse_file_identity(
                document["delta_index_identity"], label="steady delta index identity"
            ),
            "delta_overlay_identity": _parse_file_identity(
                document["delta_overlay_identity"], label="steady delta overlay identity"
            ),
            "target_identity": _parse_storage_checkpoint_identity(
                document["target_identity"]
            ),
        }
        return result
    if keys == shared | {"receipt_inventory_deferred"}:
        deferred = _boolean(
            document["receipt_inventory_deferred"],
            label="steady deferred receipt inventory flag",
        )
        if deferred is not True:
            raise ValueError("invalid steady deferred receipt inventory flag")
        deferred_result: SteadyCheckpointIdentityDeferredReceipts = {
            "source_inventory": _parse_source_inventory_identity(
                document["source_inventory"]
            ),
            "receipt_inventory_deferred": deferred,
            "source_index_identity": _parse_file_identity(
                document["source_index_identity"], label="steady source index identity"
            ),
            "delta_index_identity": _parse_file_identity(
                document["delta_index_identity"], label="steady delta index identity"
            ),
            "delta_overlay_identity": _parse_file_identity(
                document["delta_overlay_identity"], label="steady delta overlay identity"
            ),
            "target_identity": _parse_storage_checkpoint_identity(
                document["target_identity"]
            ),
        }
        return deferred_result
    raise ValueError("invalid steady checkpoint identity fields")


def steady_receipt_inventory(
    identity: SteadyCheckpointIdentity,
) -> InventoryFingerprint | None:
    value = identity.get("receipt_inventory")
    if value is None:
        return None
    return _parse_inventory_fingerprint(value, label="steady receipt inventory")


def _parse_steady_summary(value: object) -> SteadySummary:
    expected = {
        "files_seen", "loose_files_seen", "bundle_manifests_seen", "bundles_valid",
        "bundled_sources_seen", "sources_seen_total", "sources_after_deduplication",
        "orphan_bundles", "files_imported_or_confirmed", "files_unchanged",
        "receipts_written", "receipts_reused", "receipts_deferred",
        "loose_sources_imported_or_confirmed", "bundled_sources_imported_or_confirmed",
        "events_imported", "events_skipped_existing", "target_scans",
        "target_records_scanned", "identity_index_mode", "identity_index_full_rebuild",
        "identity_index_entries_after", "source_index_mode", "source_index_file_bytes",
        "sources_reused", "sources_revalidated", "sources_changed", "sources_added",
        "sources_removed", "source_bytes_read", "source_bytes_hashed",
        "source_events_validated",
    }
    document = _exact_object(value, expected, label="steady checkpoint summary")
    return {
        "files_seen": _integer(document["files_seen"], label="steady files seen"),
        "loose_files_seen": _integer(document["loose_files_seen"], label="steady loose files seen"),
        "bundle_manifests_seen": _integer(document["bundle_manifests_seen"], label="steady bundle manifests seen"),
        "bundles_valid": _integer(document["bundles_valid"], label="steady valid bundles"),
        "bundled_sources_seen": _integer(document["bundled_sources_seen"], label="steady bundled sources seen"),
        "sources_seen_total": _integer(document["sources_seen_total"], label="steady sources seen total"),
        "sources_after_deduplication": _integer(document["sources_after_deduplication"], label="steady deduplicated sources"),
        "orphan_bundles": _integer(document["orphan_bundles"], label="steady orphan bundles"),
        "files_imported_or_confirmed": _integer(document["files_imported_or_confirmed"], label="steady confirmed files"),
        "files_unchanged": _integer(document["files_unchanged"], label="steady unchanged files"),
        "receipts_written": _integer(document["receipts_written"], label="steady receipts written"),
        "receipts_reused": _integer(document["receipts_reused"], label="steady receipts reused"),
        "receipts_deferred": _integer(document["receipts_deferred"], label="steady receipts deferred"),
        "loose_sources_imported_or_confirmed": _integer(document["loose_sources_imported_or_confirmed"], label="steady loose sources confirmed"),
        "bundled_sources_imported_or_confirmed": _integer(document["bundled_sources_imported_or_confirmed"], label="steady bundled sources confirmed"),
        "events_imported": _integer(document["events_imported"], label="steady events imported"),
        "events_skipped_existing": _integer(document["events_skipped_existing"], label="steady events skipped"),
        "target_scans": _integer(document["target_scans"], label="steady target scans"),
        "target_records_scanned": _integer(document["target_records_scanned"], label="steady target records scanned"),
        "identity_index_mode": _string(document["identity_index_mode"], label="steady identity index mode"),
        "identity_index_full_rebuild": _boolean(document["identity_index_full_rebuild"], label="steady identity index rebuild flag"),
        "identity_index_entries_after": _integer(document["identity_index_entries_after"], label="steady identity index entries"),
        "source_index_mode": _string(document["source_index_mode"], label="steady source index mode"),
        "source_index_file_bytes": _integer(document["source_index_file_bytes"], label="steady source index bytes"),
        "sources_reused": _integer(document["sources_reused"], label="steady sources reused"),
        "sources_revalidated": _integer(document["sources_revalidated"], label="steady sources revalidated"),
        "sources_changed": _integer(document["sources_changed"], label="steady sources changed"),
        "sources_added": _integer(document["sources_added"], label="steady sources added"),
        "sources_removed": _integer(document["sources_removed"], label="steady sources removed"),
        "source_bytes_read": _integer(document["source_bytes_read"], label="steady source bytes read"),
        "source_bytes_hashed": _integer(document["source_bytes_hashed"], label="steady source bytes hashed"),
        "source_events_validated": _integer(document["source_events_validated"], label="steady source events validated"),
    }


def parse_steady_checkpoint_document(value: object) -> SteadyCheckpointDocument:
    document = _exact_object(
        value,
        {
            "schema_version",
            "source_dir",
            "selection_contract",
            "identity",
            "summary",
            "recorded_at",
            "historical_only",
            "does_not_establish",
            "checkpoint_sha256",
        },
        label="steady checkpoint",
    )
    return {
        "schema_version": _string(document["schema_version"], label="steady checkpoint schema"),
        "source_dir": _string(document["source_dir"], label="steady checkpoint source directory"),
        "selection_contract": _strings(
            document["selection_contract"], label="steady checkpoint selection contract"
        ),
        "identity": _parse_steady_checkpoint_identity(document["identity"]),
        "summary": _parse_steady_summary(document["summary"]),
        "recorded_at": _string(document["recorded_at"], label="steady checkpoint timestamp"),
        "historical_only": _boolean(
            document["historical_only"], label="steady checkpoint historical flag"
        ),
        "does_not_establish": _strings(
            document["does_not_establish"], label="steady checkpoint authority boundary"
        ),
        "checkpoint_sha256": _string(
            document["checkpoint_sha256"], label="steady checkpoint digest"
        ),
    }


def parse_delta_source_record(value: object) -> DeltaSourceRecord:
    document = _exact_object(
        value,
        {
            "source_path",
            "source_sha256",
            "source_bytes",
            "event_count",
            "source_identity",
        },
        label="delta-index source",
    )
    return {
        "source_path": _string(document["source_path"], label="delta-index source path"),
        "source_sha256": _string(document["source_sha256"], label="delta-index source digest"),
        "source_bytes": _integer(document["source_bytes"], label="delta-index source byte count"),
        "event_count": _integer(document["event_count"], label="delta-index source event count"),
        "source_identity": document["source_identity"],
    }

def parse_delta_bundle_record(value: object) -> DeltaBundleRecord:
    document = _exact_object(
        value,
        {
            "manifest_path",
            "manifest_identity",
            "bundle_path",
            "bundle_identity",
            "source_paths",
            "source_count",
            "event_count",
        },
        label="delta-index bundle",
    )
    return {
        "manifest_path": _string(document["manifest_path"], label="delta-index manifest path"),
        "manifest_identity": document["manifest_identity"],
        "bundle_path": _string(document["bundle_path"], label="delta-index bundle path"),
        "bundle_identity": document["bundle_identity"],
        "source_paths": _strings(
            document["source_paths"], label="delta-index archived source paths"
        ),
        "source_count": _integer(document["source_count"], label="delta-index bundle source count"),
        "event_count": _integer(document["event_count"], label="delta-index bundle event count"),
    }


def parse_delta_index_document(value: object) -> DeltaIndexDocument:
    document = _exact_object(
        value,
        {
            "schema_version",
            "source_dir",
            "selection_contract",
            "loose_sources",
            "bundles",
            "source_count",
            "event_count",
            "recorded_at",
            "historical_only",
            "does_not_establish",
            "index_sha256",
        },
        label="delta-index",
    )
    return {
        "schema_version": _string(document["schema_version"], label="delta-index schema"),
        "source_dir": _string(document["source_dir"], label="delta-index source directory"),
        "selection_contract": _strings(
            document["selection_contract"], label="delta-index selection contract"
        ),
        "loose_sources": [
            parse_delta_source_record(item)
            for item in _objects(
                document["loose_sources"], label="delta-index loose inventory"
            )
        ],
        "bundles": [
            parse_delta_bundle_record(item)
            for item in _objects(
                document["bundles"], label="delta-index bundle inventory"
            )
        ],
        "source_count": _integer(document["source_count"], label="delta-index source count"),
        "event_count": _integer(document["event_count"], label="delta-index event count"),
        "recorded_at": _string(document["recorded_at"], label="delta-index timestamp"),
        "historical_only": _boolean(document["historical_only"], label="delta-index historical flag"),
        "does_not_establish": _strings(
            document["does_not_establish"], label="delta-index authority boundary"
        ),
        "index_sha256": _string(document["index_sha256"], label="delta-index digest"),
    }

def parse_delta_overlay_document(value: object) -> DeltaOverlayDocument:
    document = _exact_object(
        value,
        {
            "schema_version",
            "source_dir",
            "base_index_sha256",
            "records",
            "record_count",
            "recorded_at",
            "historical_only",
            "does_not_establish",
            "overlay_sha256",
        },
        label="delta-overlay",
    )
    return {
        "schema_version": _string(document["schema_version"], label="delta-overlay schema"),
        "source_dir": _string(document["source_dir"], label="delta-overlay source directory"),
        "base_index_sha256": _string(
            document["base_index_sha256"], label="delta-overlay base index digest"
        ),
        "records": [
            parse_delta_source_record(item)
            for item in _objects(document["records"], label="delta-overlay records")
        ],
        "record_count": _integer(document["record_count"], label="delta-overlay record count"),
        "recorded_at": _string(document["recorded_at"], label="delta-overlay timestamp"),
        "historical_only": _boolean(document["historical_only"], label="delta-overlay historical flag"),
        "does_not_establish": _strings(
            document["does_not_establish"], label="delta-overlay authority boundary"
        ),
        "overlay_sha256": _string(document["overlay_sha256"], label="delta-overlay digest"),
    }
