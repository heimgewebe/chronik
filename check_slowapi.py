import slowapi_compat  # noqa: F401

from limits import RateLimitItemPerMinute
from slowapi.errors import RateLimitExceeded

limit = RateLimitItemPerMinute(1)
try:
    raise RateLimitExceeded(limit)
except RateLimitExceeded as e:
    print(dir(e))
