"""Policy layer: decide ALLOW / ASK / DENY from a risk level, decoupled from
risk assessment itself.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum


class Decision(str, Enum):
    """Policy decision."""
    ALLOW = "allow"     # pass through
    ASK = "ask"         # needs human confirmation
    REVIEW = "review"   # cannot be judged statically -> route to the supervisor
    DENY = "deny"       # reject outright


# Level -> numeric rank (for comparisons). UNKNOWN is deliberately absent: it is
# NOT "more dangerous than high", it is *unrankable*. Ranking it numerically is
# what silently turned UNKNOWN into DENY (see _decide_by_rank).
_LEVEL_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2}

# The only level string that means "unrankable"
_UNKNOWN = "unknown"


def _level_val(level: str | None) -> int | None:
    """Rank a level for comparison; None = unrankable/missing.

    - None (non-tool event)      -> None
    - "unknown"                  -> None  (unrankable, NOT fail-closed high)
    - "low"/"medium"/"high"      -> 0/1/2
    - any other bogus string     -> fail-closed as high (caller decides)
    """
    if level is None:
        return None
    if level == _UNKNOWN:
        return None
    return _LEVEL_ORDER.get(level)


def _rank(level: str | None) -> int | None:
    """Comparable rank, or None when the level cannot be ranked.

    A *bogus* string (typo, unknown future level) is still fail-closed as high;
    only the explicit "unknown" grade and None mean "unrankable".
    """
    if level is None or level == _UNKNOWN:
        return None
    return _LEVEL_ORDER.get(level, _LEVEL_ORDER["high"])


class PolicyBase(ABC):
    """Policy base class."""

    @abstractmethod
    def decide(self, level: str | None, *, has_opaque: bool = False) -> Decision:
        ...


class NeverAsk(PolicyBase):
    """Allow everything (observe mode)."""

    def decide(self, level: str | None, *, has_opaque: bool = False) -> Decision:
        return Decision.ALLOW


class AskRisky(PolicyBase):
    """Threshold-based: above -> DENY, equal -> ASK, below -> ALLOW.

    UNKNOWN -> ASK: a human is present, so just ask instead of guessing.
    """

    def __init__(self, threshold: str = "high") -> None:
        self._threshold = _LEVEL_ORDER.get(threshold, _LEVEL_ORDER["high"])

    def decide(self, level: str | None, *, has_opaque: bool = False) -> Decision:
        if level is None:
            # Non-tool event; opaque content without a grade -> ask conservatively
            return Decision.ASK if has_opaque else Decision.ALLOW
        if level == _UNKNOWN:
            return Decision.ASK
        val = _rank(level)
        assert val is not None
        if val > self._threshold:
            return Decision.DENY
        if val == self._threshold:
            return Decision.ASK
        return Decision.ALLOW


class DenyRisky(PolicyBase):
    """Deny at or above the threshold (unattended scenarios).

    UNKNOWN -> REVIEW, *not* DENY. This is the bug fix: the old code ranked
    "unknown" as high via `dict.get(level, high)`, so an unrankable command was
    denied exactly like a HIGH one, with no way to tell the two apart and no
    route for a supervisor to approve it. UNKNOWN now hands off to the review
    queue (see qoder_guard.review); the caller decides the timeout fallback.
    """

    def __init__(self, threshold: str = "high") -> None:
        self._threshold = _LEVEL_ORDER.get(threshold, _LEVEL_ORDER["high"])

    def decide(self, level: str | None, *, has_opaque: bool = False) -> Decision:
        if level is None:
            return Decision.ALLOW
        if level == _UNKNOWN:
            return Decision.REVIEW
        val = _rank(level)
        assert val is not None
        if val >= self._threshold:
            return Decision.DENY
        return Decision.ALLOW


# -- Self-test -------------------------------------------------------------
if __name__ == "__main__":
    # -- NeverAsk --
    na = NeverAsk()
    assert na.decide(None) == Decision.ALLOW
    assert na.decide("low") == Decision.ALLOW
    assert na.decide("medium") == Decision.ALLOW
    assert na.decide("high") == Decision.ALLOW
    assert na.decide("unknown") == Decision.ALLOW
    assert na.decide("high", has_opaque=True) == Decision.ALLOW
    assert na.decide("bogus") == Decision.ALLOW  # invalid level still allowed

    # -- AskRisky(threshold="high") --
    ah = AskRisky(threshold="high")
    assert ah.decide(None) == Decision.ALLOW            # non-tool event -> ALLOW
    assert ah.decide("low") == Decision.ALLOW            # below threshold
    assert ah.decide("medium") == Decision.ALLOW         # below threshold
    assert ah.decide("high") == Decision.ASK             # equal to threshold
    assert ah.decide("unknown") == Decision.ASK          # unrankable -> ask a human
    assert ah.decide(None, has_opaque=True) == Decision.ASK  # opaque, no grade -> ask

    # -- AskRisky(threshold="medium") --
    am = AskRisky(threshold="medium")
    assert am.decide("low") == Decision.ALLOW
    assert am.decide("medium") == Decision.ASK
    assert am.decide("high") == Decision.DENY            # above threshold

    # -- AskRisky invalid level -> fail-closed as high --
    assert ah.decide("bogus") == Decision.ASK            # treated as high = threshold

    # -- DenyRisky(threshold="high") --
    dh = DenyRisky(threshold="high")
    assert dh.decide(None) == Decision.ALLOW
    assert dh.decide("low") == Decision.ALLOW
    assert dh.decide("medium") == Decision.ALLOW
    assert dh.decide("high") == Decision.DENY            # equal to threshold -> DENY
    # UNKNOWN must NOT be denied like HIGH -- it is routed for review instead.
    # Regression: the old code mapped unknown -> high via .get(level, high).
    assert dh.decide("unknown") == Decision.REVIEW
    assert dh.decide("unknown") != dh.decide("high")

    # -- DenyRisky(threshold="medium") --
    dm = DenyRisky(threshold="medium")
    assert dm.decide("low") == Decision.ALLOW
    assert dm.decide("medium") == Decision.DENY
    assert dm.decide("high") == Decision.DENY
    assert dm.decide("unknown") == Decision.REVIEW       # threshold-independent

    # -- DenyRisky invalid level -> fail-closed --
    assert dh.decide("bogus") == Decision.DENY           # treated as high >= threshold

    # -- Ranking helper --
    assert _rank("low") == 0 and _rank("medium") == 1 and _rank("high") == 2
    assert _rank("unknown") is None and _rank(None) is None
    assert _rank("bogus") == 2                            # bogus still fail-closed

    print("policy: all assertions passed")
