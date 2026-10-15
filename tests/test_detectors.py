"""Detector characterization with PATH-shimmed kubectl/curl (no cluster needed), and arming
hygiene for per-scenario validate runs. Author: d3vn0mi (RavenSec)."""
import json
import os
import stat

import pytest

from datsu import get
from datsu.arming import METADATA
from datsu.context import Context


@pytest.fixture
def shim(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()

    def make(name, body):
        p = bindir / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)

    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    return make


def test_k803_detects_hostpath_root_pod(shim, tmp_path):
    pods = {"items": [{"metadata": {"namespace": "datsu-arm", "name": "datsu-arm-k8-03"},
                       "spec": {"volumes": [{"name": "kube-api-access", "projected": {}},
                                            {"name": "h", "hostPath": {"path": "/"}}]}}]}
    (tmp_path / "pods.json").write_text(json.dumps(pods))
    shim("kubectl", f'cat "{tmp_path}/pods.json"\n')
    d = get("K8-03").detect(Context())
    assert d.present is True and "datsu-arm/datsu-arm-k8-03" in d.evidence


def test_k803_ignores_other_hostpaths(shim, tmp_path):
    pods = {"items": [{"metadata": {"namespace": "x", "name": "p"},
                       "spec": {"volumes": [{"name": "h", "hostPath": {"path": "/var/log"}}]}}]}
    (tmp_path / "pods.json").write_text(json.dumps(pods))
    shim("kubectl", f'cat "{tmp_path}/pods.json"\n')
    assert get("K8-03").detect(Context()).present is False


def _curl(shim, code, body):
    # emulate `curl -sk ... -w "\n%{http_code}" URL`: body, newline, status code
    shim("curl", f"printf '%s\\n%s' '{body}' '{code}'\n")


def test_k812_anonymous_200_present(shim):
    _curl(shim, 200, '{"kind":"APIVersions"}')
    assert get("K8-12").detect(Context()).present is True


def test_k812_anonymous_forbidden_counts_as_anon_enabled(shim):
    _curl(shim, 403, '{"kind":"Status","message":"forbidden: User \\"system:anonymous\\" cannot get path \\"/api\\"","code":403}')
    d = get("K8-12").detect(Context())
    assert d.present is True and "anonymous" in d.evidence


def test_k812_unauthorized_is_absent(shim):
    _curl(shim, 401, '{"kind":"Status","code":401}')
    assert get("K8-12").detect(Context()).present is False


def test_namespace_cleanups_wait_for_deletion():
    """Per-scenario validate re-creates the shared datsu-arm namespace right after the previous
    scenario's cleanup; a non-waiting delete leaves it Terminating, the next arm fails, and the
    detector reports a false MISS (the v0.4.0 'namespace churn')."""
    for sid, m in METADATA.items():
        c = m.get("cleanup") or ""
        if "delete ns" in c:
            assert "--wait=false" not in c and "--wait=true" in c, sid
