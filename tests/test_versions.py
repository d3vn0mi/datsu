"""Version comparison used by every version/CVE detector, including -rcN pre-releases.
Floors come from each scenario's own note. Author: d3vn0mi (RavenSec)."""
import os
import stat

import pytest

from datsu import get
from datsu.context import Context
from datsu.scenarios import _ver_key


@pytest.mark.parametrize("a,b,less", [
    ("1.0.0-rc6", "1.0.0-rc95", True),     # rc ordering is numeric, not lexical
    ("1.0.0-rc95", "1.0.0", True),          # a pre-release sorts before its final release
    ("1.0.0", "1.0.0-rc95", False),
    ("1.1.11", "1.1.12", True),
    ("1.1.12", "1.1.12", False),
    ("18.09.1", "18.9.2", True),            # zero-padded docker versions
    ("v0.12.4", "0.12.5", True),            # leading v
    ("6.8.0-139-generic", "5.17", False),   # kernel build suffix is not a pre-release
    ("5.16.20-1-generic", "5.17", True),
    ("1.2.7", "1.2.8", True),
])
def test_ver_key_ordering(a, b, less):
    assert (_ver_key(a) < _ver_key(b)) is less


@pytest.fixture
def fake_runc(tmp_path, monkeypatch):
    def make(version):
        p = tmp_path / "runc"
        p.write_text(f"#!/bin/sh\necho 'runc version {version}'\necho 'spec: 1.0.1'\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
        monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    return make


@pytest.mark.parametrize("version,sid,present", [
    ("1.0.0-rc6", "DK-16", True),
    ("1.0.0-rc6", "DK-21", True),    # CVE-2021-30465 fixed in 1.0.0-rc95 (DK-21 note)
    ("1.0.0-rc95", "DK-21", False),
    ("1.0.0", "DK-21", False),       # was a false PRESENT with the old "1.0.2" floor
    ("1.0.1", "DK-21", False),
    ("1.1.11", "DK-16", True),
    ("1.1.12", "DK-16", False),
    ("1.2.7", "DK-17", True),
    ("1.2.8", "DK-17", False),
])
def test_runc_detectors(fake_runc, version, sid, present):
    fake_runc(version)
    assert get(sid).detect(Context()).present is present
