import slowapi_compat  # noqa: F401

from limits import RateLimitItemPerMinute
from slowapi.errors import RateLimitExceeded


def test_rate_limit_exceeded_init_handles_missing_error_message():
    limit = RateLimitItemPerMinute(1)

    try:
        exc = RateLimitExceeded(limit)
    except AttributeError as err:  # pragma: no cover - guards regression
        raise AssertionError("RateLimitExceeded should not access missing error_message") from err

    assert "1 per 1 minute" in str(exc)
    assert "Rate limit exceeded" in limit.error_message
    assert limit.limit is limit
