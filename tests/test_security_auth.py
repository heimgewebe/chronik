import app as app_module
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app import app

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.mark.parametrize(
    ("configured", "provided", "expected_tokens", "expected_status"),
    [
        ("only", "only", ("only",), None),
        ("first,second", "first", ("first", "second"), None),
        (
            "first,second,third",
            "third",
            ("first", "second", "third"),
            None,
        ),
        (
            "alpha,, beta\nalpha,\r\n gamma,beta",
            "invalid",
            ("alpha", "beta", "gamma"),
            401,
        ),
    ],
    ids=[
        "single-match",
        "first-match",
        "last-match",
        "no-match-with-empty-and-duplicate-entries",
    ],
)
def test_auth_compares_every_deduplicated_token(
    monkeypatch, configured, provided, expected_tokens, expected_status
):
    monkeypatch.setenv("CHRONIK_TOKEN", configured)
    comparisons = []

    def recording_compare_digest(candidate, configured_token):
        comparisons.append((candidate, configured_token))
        return candidate == configured_token

    monkeypatch.setattr(
        app_module.secrets, "compare_digest", recording_compare_digest
    )

    if expected_status is None:
        app_module._require_auth(provided)
    else:
        with pytest.raises(HTTPException) as exc_info:
            app_module._require_auth(provided)
        assert exc_info.value.status_code == expected_status

    assert comparisons == [(provided, token) for token in expected_tokens]


def test_auth_all_empty_config_fails_closed_without_comparison(monkeypatch):
    monkeypatch.setenv("CHRONIK_TOKEN", ", ,\n\r")

    def unexpected_compare_digest(candidate, configured_token):
        pytest.fail("compare_digest called without a configured token")

    monkeypatch.setattr(
        app_module.secrets, "compare_digest", unexpected_compare_digest
    )

    with pytest.raises(HTTPException) as exc_info:
        app_module._require_auth("candidate")

    assert exc_info.value.status_code == 500

def test_auth_single_token(client, monkeypatch):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret123")
    response = client.get("/health", headers={"X-Auth": "secret123"})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_auth_multiple_tokens_comma(client, monkeypatch):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret1,secret2,secret3")

    # Test first token
    response = client.get("/health", headers={"X-Auth": "secret1"})
    assert response.status_code == 200

    # Test middle token
    response = client.get("/health", headers={"X-Auth": "secret2"})
    assert response.status_code == 200

    # Test last token
    response = client.get("/health", headers={"X-Auth": "secret3"})
    assert response.status_code == 200

    # Test invalid token
    response = client.get("/health", headers={"X-Auth": "wrong"})
    assert response.status_code == 401

def test_auth_multiple_tokens_newline(client, monkeypatch):
    monkeypatch.setenv("CHRONIK_TOKEN", "token-a\ntoken-b\ntoken-c")

    response = client.get("/health", headers={"X-Auth": "token-b"})
    assert response.status_code == 200

    response = client.get("/health", headers={"X-Auth": "token-a"})
    assert response.status_code == 200

def test_auth_multiple_tokens_crlf(client, monkeypatch):
    # CRLF compatibility test
    monkeypatch.setenv("CHRONIK_TOKEN", "win-token1\r\nwin-token2")

    response = client.get("/health", headers={"X-Auth": "win-token1"})
    assert response.status_code == 200

    response = client.get("/health", headers={"X-Auth": "win-token2"})
    assert response.status_code == 200

def test_auth_multiple_tokens_mixed_and_whitespace(client, monkeypatch):
    monkeypatch.setenv("CHRONIK_TOKEN", "  token1 , token2\ntoken3, ")

    for t in ["token1", "token2", "token3"]:
        response = client.get("/health", headers={"X-Auth": t})
        assert response.status_code == 200, f"Token {t} should be valid"

    response = client.get("/health", headers={"X-Auth": "token1 "})
    assert response.status_code == 401, "Trailing space in provided token should fail if not in config"

def test_auth_empty_token_in_list_ignored(client, monkeypatch):
    # This ensures that a misconfiguration like "secret1,,secret2" doesn't allow empty X-Auth
    monkeypatch.setenv("CHRONIK_TOKEN", "secret1,,secret2")

    response = client.get("/health", headers={"X-Auth": ""})
    assert response.status_code == 401

    response = client.get("/health", headers={"X-Auth": "secret1"})
    assert response.status_code == 200

def test_auth_duplicate_tokens(client, monkeypatch):
    # Duplicates should be handled gracefully (deduplicated)
    monkeypatch.setenv("CHRONIK_TOKEN", "dup,dup,other")

    response = client.get("/health", headers={"X-Auth": "dup"})
    assert response.status_code == 200

    response = client.get("/health", headers={"X-Auth": "other"})
    assert response.status_code == 200

def test_auth_dynamic_token_rotation_no_restart(client, monkeypatch):
    # Verifies that the cache invalidates correctly when the environment changes.

    # 1. Start with one token
    monkeypatch.setenv("CHRONIK_TOKEN", "token1")
    assert client.get("/health", headers={"X-Auth": "token1"}).status_code == 200
    assert client.get("/health", headers={"X-Auth": "token2"}).status_code == 401

    # 2. Rotate to two tokens
    monkeypatch.setenv("CHRONIK_TOKEN", "token1,token2")
    # Cache should invalidate and recognize both
    assert client.get("/health", headers={"X-Auth": "token1"}).status_code == 200
    assert client.get("/health", headers={"X-Auth": "token2"}).status_code == 200

    # 3. Remove old token
    monkeypatch.setenv("CHRONIK_TOKEN", "token2")
    assert client.get("/health", headers={"X-Auth": "token1"}).status_code == 401
    assert client.get("/health", headers={"X-Auth": "token2"}).status_code == 200

def test_auth_no_tokens_configured(client, monkeypatch):
    monkeypatch.setenv("CHRONIK_TOKEN", "")
    response = client.get("/health", headers={"X-Auth": "any"})
    assert response.status_code == 500
    assert "server misconfigured" in response.text

def test_auth_header_missing(client, monkeypatch):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    response = client.get("/health")
    assert response.status_code == 401

def test_auth_wrong_token(client, monkeypatch):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    response = client.get("/health", headers={"X-Auth": "wrong"})
    assert response.status_code == 401
