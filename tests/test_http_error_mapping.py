import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import app
import storage


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    monkeypatch.setenv("CHRONIK_INTEGRITY_ENABLED", "0")
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    app.limiter.reset()
    try:
        with TestClient(app.app) as test_client:
            yield test_client
    finally:
        app.limiter.reset()


@pytest.mark.parametrize(
    ("error", "status", "detail"),
    [
        (storage.StorageCursorError("internal cursor detail"), 400, "cursor must point to a record boundary"),
        (storage.StorageBusyError("internal lock path"), 429, "busy, try again"),
        (storage.StorageFullError("device /secret is full"), 507, "insufficient storage"),
        (storage.StorageConflictError("event_id", "secret-event-id"), 409, "conflicting event_id"),
        (storage.StorageRequiredIdentityError("event_id"), 400, "missing event_id"),
    ],
)
def test_storage_contract_errors_have_bounded_http_mapping(error, status, detail):
    with pytest.raises(HTTPException) as caught:
        app._raise_storage_http_exception(error)

    assert caught.value.status_code == status
    assert caught.value.detail == detail
    assert "secret-event-id" not in str(caught.value.detail)


def test_generic_storage_error_is_always_masked_as_server_error():
    error = storage.StorageError("invalid target /private/storage/path")

    with pytest.raises(HTTPException) as caught:
        app._raise_storage_http_exception(error)

    assert caught.value.status_code == 500
    assert caught.value.detail == "storage error"
    assert "private" not in str(caught.value.detail)
    assert "invalid target" not in str(caught.value.detail)


def test_identity_index_conflict_message_cannot_masquerade_as_client_conflict():
    error = storage.StorageError("conflicting event_id: damaged-ledger")

    with pytest.raises(HTTPException) as caught:
        app._raise_storage_http_exception(error, domain="agent.ledger")

    assert caught.value.status_code == 500
    assert caught.value.detail == "storage error"


@pytest.mark.parametrize(
    ("path", "storage_attr"),
    [
        ("/v1/events?domain=example.com", "scan_domain"),
        ("/v1/latest?domain=example.com", "read_last_line"),
        ("/v1/tail?domain=example.com", "read_tail"),
    ],
)
def test_read_endpoints_mask_internal_storage_failures(
    client, monkeypatch, path, storage_attr
):
    def fail_storage(*_args, **_kwargs):
        raise storage.StorageError("backend failure at /private/ledger.jsonl")

    monkeypatch.setattr(app, storage_attr, fail_storage)

    response = client.get(path, headers={"X-Auth": "test-token"})

    assert response.status_code == 500
    assert response.json() == {"detail": "storage error"}
    assert "private" not in response.text
