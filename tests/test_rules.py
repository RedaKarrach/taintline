import pytest

from taintline.rules.engine import RuleEngine, load_rules
from taintline.schema import group_sessions
from taintline.simulate.scenarios import get_scenario
from taintline.taint import TaintEngine
from taintline.toolclass import ToolClassifier


@pytest.fixture(scope="module")
def engine():
    return RuleEngine(load_rules())


def _findings(engine, events, target_session=None):
    sessions = group_sessions(events)
    analyses = TaintEngine(ToolClassifier()).analyze_sessions(sessions)
    if target_session:
        analyses = [a for a in analyses if a.session.id == target_session]
    out = []
    for a in analyses:
        out.extend(engine.evaluate(a))
    return out


def test_builtin_rules_load():
    rs = load_rules()
    assert len(rs) >= 15
    ids = {r.id for r in rs}
    assert "TL-INJ-001" in ids
    assert "TL-EXF-002" in ids


@pytest.mark.parametrize(
    "scenario,expected",
    [
        ("indirect_exfil", "TL-INJ-001"),
        ("tool_poisoning", "TL-SCH-001"),
        ("chunked_exfil", "TL-EXF-002"),
        ("cloud_privesc", "TL-SEQ-002"),
        ("destructive_runaway", "TL-AGY-001"),
        ("jailbreak_then_action", "TL-JBK-001"),
        ("output_beacon", "TL-EXF-006"),
        ("pii_exfil", "TL-EXF-003"),
    ],
)
def test_scenario_fires_expected_rule(engine, scenario, expected):
    findings = _findings(engine, get_scenario(scenario).build())
    ids = {f.rule_id for f in findings}
    assert expected in ids, f"{scenario}: expected {expected}, got {sorted(ids)}"


def test_memory_poison_cross_session(engine):
    events = get_scenario("memory_poison_write").build() + get_scenario("memory_poison_trigger").build()
    findings = _findings(engine, events, target_session="atk-mem-trigger")
    ids = {f.rule_id for f in findings}
    assert "TL-MEM-003" in ids


def test_benign_sessions_no_high_findings(engine):
    for name in ["benign_authorized_send", "benign_security_article", "benign_authorized_cleanup"]:
        findings = _findings(engine, get_scenario(name).build())
        high = [f for f in findings if f.rank >= 3]
        assert not high, f"{name} produced high findings: {[f.rule_id for f in high]}"


def test_custom_rule_file(tmp_path):
    rule = tmp_path / "custom.yaml"
    rule.write_text(
        "id: TEST-001\ntitle: any exfil sink\nseverity: low\nmatch:\n  type: content\n  on_kind: [tool_call]\n  tool_class: [network_egress]\n",
        encoding="utf-8",
    )
    rs = load_rules([str(rule)], include_builtin=False)
    assert len(rs) == 1 and rs[0].id == "TEST-001"
