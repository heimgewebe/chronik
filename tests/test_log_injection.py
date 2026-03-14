import logging
from fastapi.testclient import TestClient
from app import app

def test_log_injection_request_id(caplog, monkeypatch):
    # Ensure deterministic environment for auth and disable integrity background logic
    monkeypatch.setenv("CHRONIK_TOKEN", "test_token")
    monkeypatch.setenv("CHRONIK_INTEGRITY_ENABLED", "0")

    client = TestClient(app)
    malicious_rid = "123\nERROR: spoofed error message"

    # We need to ensure the logger is at least at INFO level to capture the "access" log
    with caplog.at_level(logging.INFO, logger="chronik"):
        # Send request so middleware logs the sanitized request_id
        response = client.get(
            "/health",
            headers={"X-Request-ID": malicious_rid, "X-Auth": "test_token"},
        )
        assert response.status_code in (200, 401, 403)

    # Check if the malicious RID is sanitized in the logs
    log_messages = [rec.request_id for rec in caplog.records if hasattr(rec, "request_id")]
    expected_rid = "123_ERROR__spoofed_error_message"
    assert expected_rid in log_messages
    assert malicious_rid not in log_messages
