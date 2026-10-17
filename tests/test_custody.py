import json

from taintline.custody import build_manifest, verify_manifest
from taintline.schema import load_jsonl
from taintline.simulate.scenarios import get_scenario
from taintline.schema import dump_jsonl


def _write_trace(tmp_path, name="t.jsonl"):
    p = tmp_path / name
    dump_jsonl(get_scenario("indirect_exfil").build(), str(p))
    return str(p)


def test_manifest_build_and_verify(tmp_path):
    trace = _write_trace(tmp_path)
    events = load_jsonl(trace)
    man = build_manifest(trace, events)
    mp = tmp_path / "m.json"
    mp.write_text(json.dumps(man), encoding="utf-8")
    res = verify_manifest(str(mp), trace)
    assert res["ok"] is True
    assert res["file_hash_ok"] and res["chain_ok"]


def test_tamper_detected(tmp_path):
    trace = _write_trace(tmp_path)
    events = load_jsonl(trace)
    man = build_manifest(trace, events)
    mp = tmp_path / "m.json"
    mp.write_text(json.dumps(man), encoding="utf-8")
    # tamper an event's actual content (the exfiltrated AWS key line)
    lines = open(trace, encoding="utf-8").read().splitlines()
    idx = next(i for i, ln in enumerate(lines) if "aws_access_key_id" in ln)
    lines[idx] = lines[idx].replace("AKIAFAKE", "AKIAREAL")
    with open(trace, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    res = verify_manifest(str(mp), trace)
    assert res["ok"] is False
    assert res["chain_ok"] is False
    assert res["first_divergence"] is not None
