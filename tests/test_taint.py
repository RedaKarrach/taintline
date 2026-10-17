from taintline.schema import group_sessions
from taintline.simulate.scenarios import get_scenario
from taintline.taint import TaintEngine
from taintline.toolclass import ToolClassifier


def _analyze(events):
    sessions = group_sessions(events)
    return TaintEngine(ToolClassifier()).analyze_sessions(sessions)


def test_indirect_exfil_produces_flow():
    a = _analyze(get_scenario("indirect_exfil").build())[0]
    assert a.flows, "expected at least one flow"
    kinds = {f.kind for f in a.flows}
    assert "taint_path" in kinds
    assert any(f.sink_class == "network_egress" for f in a.flows)


def test_data_flow_detects_secret_in_sink():
    a = _analyze(get_scenario("indirect_exfil").build())[0]
    data = [f for f in a.flows if f.kind == "data_flow"]
    assert data, "expected a data_flow carrying the secret"
    assert any("aws" in "".join(f.details.get("secret_kinds", [])) for f in data)


def test_authorized_destination_not_flagged_as_exfil():
    a = _analyze(get_scenario("benign_authorized_send").build())[0]
    # the send goes to an address the user named; no high-confidence exfil flow
    exfil = [f for f in a.flows if f.sink_class == "email_send" and f.confidence >= 0.5 and not f.details.get("destination_authorized")]
    assert not exfil


def test_chunked_exfil_accumulates():
    a = _analyze(get_scenario("chunked_exfil").build())[0]
    chunked = [f for f in a.flows if f.kind == "chunked_data_flow"]
    assert chunked, "expected a chunked_data_flow"
    assert chunked[0].details["cumulative_coverage"] >= 0.5


def test_cross_session_memory_taint():
    write = get_scenario("memory_poison_write").build()
    trigger = get_scenario("memory_poison_trigger").build()
    analyses = _analyze(write + trigger)
    trig = [a for a in analyses if a.session.id == "atk-mem-trigger"][0]
    cross = [f for f in trig.flows if f.details.get("cross_session")]
    assert cross, "expected a cross-session flow from poisoned memory"


def test_benign_has_no_flows():
    a = _analyze(get_scenario("benign_security_article").build())[0]
    assert not [f for f in a.flows if f.confidence >= 0.5]
