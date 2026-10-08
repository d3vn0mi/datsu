"""Core data model for the escape scenario registry.

A Scenario carries both a *detector* (read-only: is this escape condition present on the
node right now?) and an *exploiter* (run the documented escape, gated). Either half can be
expressed as a shell snippet (the common case, since the underlying checks are docker /
kubectl / jq one-liners) or as a Python callable (used where the logic needs real
correlation, e.g. RBAC binding analysis).

Author: d3vn0mi (RavenSec)
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional


class Kind(str, Enum):
    DOCKER = "docker"
    K8S = "k8s"


class Repro(str, Enum):
    CONFIG = "config"     # a live misconfiguration — detectable and (if authorized) exploitable
    VERSION = "version"   # a version/CVE precondition — detect only, never auto-exploited (cyber_gate)
    NA = "n-a"            # not applicable on this platform (e.g. cloud IMDS on bare Proxmox)


class Confidence(str, Enum):
    CONCRETE = "concrete"        # bounded, single-technique escape proven in the source engagement
    DOCUMENTED = "documented"    # public documented technique, implemented bounded here
    PRECONDITION = "precondition"  # detection only; exploit needs offline tooling / is multi-step (cyber_gate)


@dataclass
class Detection:
    """Result of a read-only condition check. `present is None` means inconclusive
    (a required tool was missing), which is reported distinctly from a clean ABSENT."""
    present: Optional[bool]
    evidence: str = ""

    @property
    def state(self) -> str:
        if self.present is None:
            return "UNKNOWN"
        return "PRESENT" if self.present else "ABSENT"


@dataclass
class Exploitation:
    attempted: bool
    success: Optional[bool]
    evidence: str = ""

    @property
    def state(self) -> str:
        if not self.attempted:
            return "SKIPPED"
        if self.success is None:
            return "INCONCLUSIVE"
        return "SUCCESS" if self.success else "FAILED"


@dataclass
class Scenario:
    id: str
    kind: Kind
    repro: Repro
    vector: str
    severity: str
    note: str = ""
    triage_ref: str = ""              # cross-reference to the RavenSec triage check id, "" if none
    confidence: Confidence = Confidence.DOCUMENTED
    detect_sh: Optional[str] = None   # sh -c snippet; exit 0 == condition PRESENT, stdout == evidence
    detect_fn: Optional[Callable[["Context"], Detection]] = None
    exploit_sh: Optional[str] = None  # sh -c snippet; $MARKER in env; exit 0 == escape proven
    exploit_fn: Optional[Callable[["Context", str], Exploitation]] = None
    # validation metadata (used by `datsu validate`): the human-readable preconditions this
    # condition requires, and how to ARM it on a disposable lab so the detector can be exercised.
    preconditions: str = ""
    arm_sh: Optional[str] = None      # create the condition and LEAVE it armed (disposable lab only)
    cleanup_sh: Optional[str] = None  # tear the armed condition back down

    # ---- detection (always read-only) -------------------------------------------------
    def detect(self, ctx: "Context") -> Detection:
        if self.detect_fn is not None:
            return self.detect_fn(ctx)
        if self.detect_sh is not None:
            rc, out = ctx.sh(self.detect_sh)
            if rc == 127:  # command not found anywhere in the pipeline
                return Detection(None, _trim(out))
            return Detection(rc == 0, _trim(out))
        return Detection(None, "no detector defined")

    # ---- exploitation (state-changing; gated by the CLI) ------------------------------
    def exploit(self, ctx: "Context", marker: str) -> Exploitation:
        if self.repro is Repro.VERSION:
            return Exploitation(False, None,
                                "version/CVE precondition — detection only (cyber_gate: no live "
                                "exploitation of a version-pinned component)")
        if self.repro is Repro.NA:
            return Exploitation(False, None, "not applicable on this platform")
        if self.confidence is Confidence.PRECONDITION:
            return Exploitation(False, None,
                                "not auto-exploited — " + (self.note or "documented technique is "
                                "multi-step / needs offline tooling (cyber_gate)"))
        if self.exploit_fn is not None:
            return self.exploit_fn(ctx, marker)
        if self.exploit_sh is not None:
            rc, out = ctx.sh(self.exploit_sh, env={"MARKER": marker}, timeout=ctx.exploit_timeout)
            if rc == 127:
                return Exploitation(True, None, _trim(out))
            return Exploitation(True, rc == 0, _trim(out))
        return Exploitation(False, None, "no exploit implemented")


def _trim(s: str, n: int = 600) -> str:
    s = (s or "").strip()
    return s if len(s) <= n else s[:n] + " …[truncated]"
