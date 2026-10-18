import json

from taintline.forensics import correlate, exposed_keys_from_analyses, load_cloudtrail
from taintline.schema import group_sessions
from taintline.simulate.scenarios import get_scenario
from taintline.taint import TaintEngine
from taintline.toolclass import ToolClassifier

EXPOSED = "AKIAFAKE7EXAMPLE1234"
EXPOSED_AT = "2026-03-01T10:00:00+00:00"


def _rec(name, ts, key=EXPOSED, ip="203.0.113.9", ua="python-requests/2.31", source="iam.amazonaws.com"):
    return {
        "eventTime": ts,
        "eventName": name,
        "eventSource": source,
        "sourceIPAddress": ip,
        "userAgent": ua,
        "userIdentity": {"accessKeyId": key},
    }


def test_confirmed_abuse_sensitive_call():
    records = [
        _rec("GetCallerIdentity", "2026-02-28T09:00:00+00:00", ip="10.0.0.5", ua="aws-cli/2"),  # baseline, pre-exposure
        _rec("CreateAccessKey", "2026-03-01T10:05:00+00:00"),  # post-exposure, sensitive, new origin
    ]
    res = correlate(records, {EXPOSED: EXPOSED_AT})
    assert res.any_abuse
    v = res.verdicts[0]
    assert v.used_after_exposure and v.confirmed_abuse
    assert res.summary["sensitive_calls"] == 1


def test_new_origin_flagged_even_for_ordinary_call():
    records = [
        _rec("DescribeInstances", "2026-02-20T00:00:00+00:00", ip="10.0.0.5", ua="aws-cli/2", source="ec2.amazonaws.com"),
        _rec("DescribeInstances", "2026-03-01T11:00:00+00:00", ip="198.51.100.7", ua="curl/8", source="ec2.amazonaws.com"),
    ]
    res = correlate(records, {EXPOSED: EXPOSED_AT})
    assert res.any_abuse  # not sensitive, but a brand-new origin after exposure
    assert res.verdicts[0].hits[-1].new_origin


def test_same_origin_ordinary_call_is_used_not_abused():
    records = [
        _rec("DescribeRegions", "2026-02-20T00:00:00+00:00", ip="10.0.0.5", ua="aws-cli/2", source="ec2.amazonaws.com"),
        _rec("DescribeRegions", "2026-03-01T10:30:00+00:00", ip="10.0.0.5", ua="aws-cli/2", source="ec2.amazonaws.com"),
    ]
    res = correlate(records, {EXPOSED: EXPOSED_AT})
    v = res.verdicts[0]
    assert v.used_after_exposure and not v.confirmed_abuse


def test_logging_tamper_detected():
    res = correlate([_rec("StopLogging", "2026-03-01T10:10:00+00:00", source="cloudtrail.amazonaws.com")], {EXPOSED: EXPOSED_AT})
    assert res.summary["logging_tamper_detected"] and res.any_abuse


def test_window_excludes_old_use():
    res = correlate([_rec("GetSecretValue", "2026-06-01T00:00:00+00:00")], {EXPOSED: EXPOSED_AT}, window_hours=72)
    assert not res.verdicts[0].used_after_exposure


def test_unexposed_key_ignored():
    res = correlate([_rec("CreateAccessKey", "2026-03-01T10:05:00+00:00", key="AKIAOTHERKEY00000000")], {EXPOSED: EXPOSED_AT})
    assert not res.any_abuse


def test_loaders(tmp_path):
    recs = [_rec("GetSecretValue", "2026-03-01T10:05:00+00:00")]
    a = tmp_path / "a.json"
    a.write_text(json.dumps({"Records": recs}), encoding="utf-8")
    b = tmp_path / "b.jsonl"
    b.write_text("\n".join(json.dumps(r) for r in recs), encoding="utf-8")
    assert len(load_cloudtrail(str(a))) == 1 and len(load_cloudtrail(str(b))) == 1


def test_end_to_end_from_incident():
    events = get_scenario("indirect_exfil").build()
    analyses = TaintEngine(ToolClassifier()).analyze_sessions(group_sessions(events))
    keys = exposed_keys_from_analyses(analyses, events)
    assert EXPOSED in keys  # pulled straight from the exfil flow
    # the exfil ts is synthetic; correlate without a window constraint
    records = [_rec("AttachUserPolicy", "2026-01-01T09:10:00+00:00")]
    res = correlate(records, {EXPOSED: None})
    assert res.any_abuse
