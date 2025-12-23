from slowapi.errors import RateLimitExceeded
from limits import RateLimitItemPerMinute

limit = RateLimitItemPerMinute(1)
try:
    raise RateLimitExceeded(limit)
except RateLimitExceeded as e:
    print(dir(e))
