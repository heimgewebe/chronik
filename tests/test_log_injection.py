import logging
import uuid
import pytest
from fastapi.testclient import TestClient
from app import app

def test_log_injection_request_id(caplog):
    client = TestClient(app)
    malicious_rid = "123\nERROR: spoofed error message"

    # We need to ensure the logger is at least at INFO level to capture the "access" log
    with caplog.at_level(logging.INFO, logger="chronik"):
        response = client.get("/health", headers={"X-Request-ID": malicious_rid, "X-Auth": "test_token"})
        # Note: /health requires auth. Let's make sure it doesn't fail auth if we want to reach the middleware's finally block properly
        # Wait, the middleware's finally block ALWAYS runs.

    # Check if the malicious RID is sanitized in the logs
    log_messages = [rec.request_id for rec in caplog.records if hasattr(rec, "request_id")]
    expected_rid = "123_ERROR__spoofed_error_message"
    assert expected_rid in log_messages
    assert malicious_rid not in log_messages
