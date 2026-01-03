from slowapi.errors import RateLimitExceeded
from limits import RateLimitItemPerMinute

import slowapi_compat

limit = RateLimitItemPerMinute(1)
try:
    raise RateLimitExceeded(limit)
except RateLimitExceeded as e:
    print(dir(e))
