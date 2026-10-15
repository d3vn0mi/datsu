"""validate: classify whose object made a detector fire (own / other scenario / node-level).
Author: d3vn0mi (RavenSec)."""
from datsu.validate import report_md, scope_of


def test_scope_own_object():
    assert scope_of("DK-02", "/datsu-arm-dk-02", "docker run --name datsu-arm-dk-02 alpine") == "own"


def test_scope_own_object_compact_id():
    assert scope_of("K8-05", "kube-system/datsu-arm-k805", "") == "own"


def test_scope_other_object():
    assert scope_of("DK-01", "/datsu-arm-dk15", "docker run --name datsu-arm-dk-01 alpine") == "other"


def test_scope_own_object_named_only_in_arm():
    # DK-13 arms a user 'datsu-arm-u' whose name carries no scenario id
    assert scope_of("DK-13", "datsu-arm-u", "useradd -m datsu-arm-u; usermod -aG docker datsu-arm-u") == "own"


def test_scope_node_condition():
    assert scope_of("K8-06", "kubelet /pods -> 200", "") == "node"


def _rec(sid, result, evidence, scope):
    return {"id": sid, "vector": "v", "severity": "HIGH", "class": "docker", "repro": "config",
            "confidence": "concrete", "triage_ref": "", "preconditions": "p", "cves": [],
            "arm_steps": None, "exploit_cmd": "x",
            "q1": {"armed": True, "result": result, "evidence": evidence, "scope": scope},
            "q2": {"result": "N/A-BY-DESIGN", "evidence": ""}}


def test_report_marks_cross_hits():
    md = report_md([_rec("DK-01", "DETECTED", "/datsu-arm-dk15", "other"),
                    _rec("DK-02", "DETECTED", "/datsu-arm-dk-02", "own")], "M")
    assert "| DK-01 |" in md and "cross-hit" in md.split("| DK-01 |")[1].splitlines()[0]
    assert "cross-hit" not in md.split("| DK-02 |")[1].splitlines()[0]
    assert "1 cross-hit" in md
