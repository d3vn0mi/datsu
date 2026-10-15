"""Detectors for field techniques from CTF solves (research v2, step 4). Detection only: every
one is version- or precondition-class, so datsu never exploits them. Facts from the CVE records.
Author: d3vn0mi (RavenSec)."""
import os
import stat

import pytest

from datsu import get
from datsu.context import Context
from datsu.model import Confidence, Repro


@pytest.fixture
def env(tmp_path, monkeypatch):
    """PATH shims driven by files in tmp_path/fx: docker (ver, platform, root), ss, curl, getent_<group>."""
    fx = tmp_path / "fx"; fx.mkdir()
    bindir = tmp_path / "bin"; bindir.mkdir()
    shims = {
        "docker": 'case "$*" in *Server.Version*) cat "$FX/ver" 2>/dev/null;; '
                  '*Platform.Name*) cat "$FX/platform" 2>/dev/null;; *DockerRootDir*) cat "$FX/root" 2>/dev/null;; esac',
        "ss": 'cat "$FX/ss" 2>/dev/null; exit 0',
        "curl": 'cat "$FX/curl" 2>/dev/null || printf 000',
        "getent": '[ "$1" = group ] && cat "$FX/getent_$2" 2>/dev/null && exit 0; exit 2',
    }
    for name, body in shims.items():
        p = bindir / name
        p.write_text("#!/bin/sh\n" + body + "\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("FX", str(fx))

    def write(name, text):
        (fx / name).write_text(text)
    return write, tmp_path


@pytest.mark.parametrize("sid", ["DK-39", "DK-40", "DK-41", "DK-42"])
def test_field_scenarios_are_detect_only(sid):
    s = get(sid)
    assert s.repro is Repro.VERSION or s.confidence is Confidence.PRECONDITION
    assert s.exploit_sh is None and s.exploit_fn is None


# --- DK-39 CVE-2021-41091 ------------------------------------------------------------------

def _dataroot(tmp_path, mode):
    root = tmp_path / "docker"; (root / "overlay2").mkdir(parents=True)
    os.chmod(root / "overlay2", mode)
    return str(root)


def test_dk39_vulnerable_and_traversable(env):
    write, tmp = env
    write("ver", "20.10.8\n"); write("root", _dataroot(tmp, 0o701) + "\n")
    d = get("DK-39").detect(Context())
    assert d.present is True and "701" in d.evidence


def test_dk39_vulnerable_but_workaround_applied(env):
    write, tmp = env
    write("ver", "20.10.8\n"); write("root", _dataroot(tmp, 0o700) + "\n")
    assert get("DK-39").detect(Context()).present is False


def test_dk39_fixed_version(env):
    write, _ = env
    write("ver", "20.10.9\n")
    assert get("DK-39").detect(Context()).present is False


# --- DK-40 CVE-2025-9074 -------------------------------------------------------------------

@pytest.mark.parametrize("platform,present", [
    ("Docker Desktop 4.44.2 (202017)", True),
    ("Docker Desktop 4.44.3 (202357)", False),
    ("Docker Desktop 4.24.0 (122432)", False),   # before the affected range (4.25)
])
def test_dk40_desktop_versions(env, platform, present):
    write, _ = env
    write("platform", platform + "\n")
    assert get("DK-40").detect(Context()).present is present


def test_dk40_engine_api_reachable_from_container(env):
    write, _ = env
    write("curl", "200")
    d = get("DK-40").detect(Context())
    assert d.present is True and "192.168.65.7:2375" in d.evidence


def test_dk40_absent(env):
    assert get("DK-40").detect(Context()).present is False


# --- DK-41 dockerd TLS with readable CA key --------------------------------------------------

def _keydir(tmp_path, mode, monkeypatch):
    d = tmp_path / "etc-docker"; d.mkdir()
    k = d / "ca-key.pem"; k.write_text("x"); os.chmod(k, mode)
    monkeypatch.setenv("DATSU_DOCKER_KEY_DIRS", str(d))


def test_dk41_readable_ca_key(env, monkeypatch):
    write, tmp = env
    write("ss", "LISTEN 0 4096 *:2376 *:*\n"); _keydir(tmp, 0o644, monkeypatch)
    d = get("DK-41").detect(Context())
    assert d.present is True and "ca-key.pem" in d.evidence


def test_dk41_private_ca_key(env, monkeypatch):
    write, tmp = env
    write("ss", "LISTEN 0 4096 *:2376 *:*\n"); _keydir(tmp, 0o600, monkeypatch)
    assert get("DK-41").detect(Context()).present is False


def test_dk41_no_tls_listener(env, monkeypatch):
    _, tmp = env
    _keydir(tmp, 0o644, monkeypatch)
    assert get("DK-41").detect(Context()).present is False


# --- DK-42 lxd / lxc group -----------------------------------------------------------------

def test_dk42_lxd_member(env):
    write, _ = env
    write("getent_lxd", "lxd:x:110:alice\n")
    d = get("DK-42").detect(Context())
    assert d.present is True and "alice" in d.evidence


def test_dk42_empty_groups(env):
    write, _ = env
    write("getent_lxd", "lxd:x:110:\n")
    assert get("DK-42").detect(Context()).present is False
