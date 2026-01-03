"""Compatibility helpers for SlowAPI / limits.

The upstream ``slowapi.RateLimitExceeded`` currently expects the provided
``RateLimitItem`` to expose an ``error_message`` attribute. Recent versions of
``limits`` no longer define this attribute, which causes an ``AttributeError``
as soon as the exception is instantiated. We patch the base class once on
import so that rate-limit handling remains stable even when the dependency
versions diverge.
"""

from limits import RateLimitItem


def patch_rate_limit_item() -> None:
    """Patch RateLimitItem with properties expected by SlowAPI's exceptions."""

    if not hasattr(RateLimitItem, "error_message"):
        RateLimitItem.error_message = property(  # type: ignore[attr-defined]
            lambda self: f"Rate limit exceeded: {self}"
        )

    if not hasattr(RateLimitItem, "limit"):
        RateLimitItem.limit = property(lambda self: self)  # type: ignore[attr-defined]


# Apply the patch immediately for any importers.
patch_rate_limit_item()
