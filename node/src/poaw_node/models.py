"""Core types. The vocabulary follows SPEC.md §2 and §6."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import json

from pydantic import BaseModel, Field, field_validator

MAX_PARAMS_BYTES = 2048  # SECURITY F3: params end up in permanent, public receipts. The whole receipt is bounded separately (receipt.MAX_SIGNED_BYTES)


class Verdict(str, Enum):
    VERIFIED = "verified"
    LATE = "late"
    MISMATCH = "mismatch"
    FAILED = "failed"
    UNVERIFIABLE = "unverifiable"


class Reason(str, Enum):
    NOT_FOUND = "not_found"
    CONTENT_MISMATCH = "content_mismatch"
    TARGET_MISMATCH = "target_mismatch"
    OBSERVED_AFTER_TOLERANCE = "observed_after_tolerance"
    NO_CONNECTION = "no_connection"
    PERMISSION_DENIED = "permission_denied"
    RATE_LIMITED = "rate_limited"
    DESTINATION_UNAVAILABLE = "destination_unavailable"
    UNSUPPORTED_ACTION = "unsupported_action"
    CLAIM_AMBIGUOUS = "claim_ambiguous"
    VERIFIER_ERROR = "verifier_error"


class ClaimIn(BaseModel):
    """What an agent submits. Always untrusted (SPEC §2)."""

    client_claim_id: str = Field(min_length=1, max_length=256)
    agent_id: str = Field(min_length=1, max_length=256)
    action: str = Field(pattern=r"^[a-z0-9]+(\.[a-z0-9_]+){2}$")
    target: str = Field(min_length=1, max_length=512)
    params: dict[str, Any] = Field(default_factory=dict)
    claimed_at: datetime

    @field_validator("params")
    @classmethod
    def _small(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(v, separators=(",", ":"))) > MAX_PARAMS_BYTES:
            raise ValueError(f"params larger than {MAX_PARAMS_BYTES} bytes")
        return v

    @field_validator("claimed_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("claimed_at must include a timezone")
        return v


@dataclass(frozen=True)
class Claim:
    """A stored claim, as the verifier runner sees it."""

    id: str
    workspace_id: str
    agent_ref: str
    client_claim_id: str
    action: str
    target: str
    params: dict[str, Any]
    claimed_at: datetime
    deadline_at: datetime
    attempts: int = 0
    created_at: datetime | None = None  # when the claim was stored (drives the optional enclave window)


@dataclass(frozen=True)
class Observed:
    """The destination was read successfully. `facts` follow SPEC §4.4: IDs, timestamps, fingerprints only."""

    facts: dict[str, Any]
    outcome: Verdict  # the verifier's comparison result: VERIFIED, MISMATCH or FAILED (found / differs / absent)
    reason: Reason | None = None
    observed_at: datetime | None = None
    appeared_at: datetime | None = None  # when the outcome appeared at the destination, if known (drives LATE)
    final: bool = True  # False = "absent so far", which the runner retries until the deadline


@dataclass(frozen=True)
class Retry:
    """Couldn't decide yet (transient). The runner retries until the deadline, then gives `unverifiable`."""

    reason: Reason
    detail: str = ""


@dataclass(frozen=True)
class Unverifiable:
    """Can never be decided for this claim (no connection, unsupported, ambiguous)."""

    reason: Reason
    detail: str = ""


VerifierResult = Observed | Retry | Unverifiable


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: Reason | None
    facts: dict[str, Any] = field(default_factory=dict)
    observed_at: datetime | None = None
