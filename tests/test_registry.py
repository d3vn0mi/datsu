"""Registry integrity + CLI wiring tests. No root, no docker/kubectl needed —
these assert the catalogue is well-formed and that detect/exploit dispatch and gate correctly
(every system call is routed through Context, which is stubbed here)."""
import json

import pytest

from datsu import SCENARIOS, get
from datsu.cli import main
from datsu.model import Confidence, Detection, Exploitation, Repro, Scenario


def test_expected_catalogue_shape():
    assert len(SCENARIOS) == 93
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids)), "duplicate scenario ids"
    assert sum(s.kind.value == "docker" for s in SCENARIOS) == 38
    assert sum(s.kind.value == "k8s" for s in SCENARIOS) == 55


def test_every_config_scenario_has_a_detector():
    for s in SCENARIOS:
        if s.repro is Repro.CONFIG:
            assert s.detect_sh or s.detect_fn, f"{s.id} config scenario has no detector"


def test_version_and_na_scenarios_never_exploit():
    class _Ctx:  # exploit() for version/n-a must short-circuit before touching the system
        def sh(self, *a, **k):  # pragma: no cover - must never be called
            raise AssertionError("exploit touched the system for a non-config scenario")
    for s in SCENARIOS:
        if s.repro in (Repro.VERSION, Repro.NA):
            ex = s.exploit(_Ctx(), "M")
            assert ex.attempted is False and ex.success is None


def test_precondition_scenarios_are_detect_only():
    for s in SCENARIOS:
        if s.confidence is Confidence.PRECONDITION:
            ex = s.exploit(_StubCtx(), "M")
            assert ex.attempted is False, f"{s.id} is PRECONDITION but attempted an exploit"


class _StubCtx:
    """Minimal Context stand-in: records sh() calls, returns a canned result."""
    def __init__(self, rc=0, out="stub"):
        self.rc, self.out, self.calls = rc, out, []
        self.exploit_timeout = 90
    def sh(self, snippet, env=None, timeout=None):
        self.calls.append((snippet, env))
        return self.rc, self.out
    def have(self, tool):
        return True


def test_detect_sh_present_vs_absent():
    s = next(x for x in SCENARIOS if x.detect_sh)
    assert s.detect(_StubCtx(rc=0, out="esc")).present is True
    assert s.detect(_StubCtx(rc=1, out="")).present is False
    assert s.detect(_StubCtx(rc=127, out="not found")).present is None


def test_exploit_sh_passes_marker_and_reads_exit_code():
    s = next(x for x in SCENARIOS if x.exploit_sh and x.repro is Repro.CONFIG
             and x.confidence is not Confidence.PRECONDITION)
    ctx = _StubCtx(rc=0, out="done")
    ex = s.exploit(ctx, "ESCAPE_X_tok")
    assert ex.attempted and ex.success is True
    assert any(env and env.get("MARKER") == "ESCAPE_X_tok" for _, env in ctx.calls)
    assert s.exploit(_StubCtx(rc=1, out="no"), "m").success is False


def test_exploit_refuses_without_marker(capsys):
    rc = main(["exploit", "--id", "DK-01"])
    assert rc == 2
    assert "without --marker" in capsys.readouterr().err


def test_list_json_is_valid_and_complete(capsys):
    assert main(["list", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 93
    assert {"id", "class", "repro", "vector", "severity", "confidence"} <= set(data[0])


def test_get_is_case_insensitive():
    assert get("dk-01") is get("DK-01") is not None
    assert get("nope") is None
