import json

from taintline.schema import group_sessions, load_jsonl, parse_event


def test_parse_minimal_event():
    e = parse_event({"session_id": "s1", "kind": "user_message", "content": "hi"}, 0)
    assert e.session_id == "s1"
    assert e.kind == "user_message"
    assert e.text == "hi"


def test_parse_args_as_string_json():
    e = parse_event({"session_id": "s", "kind": "tool_call", "tool": "x", "args": '{"a": 1}'}, 0)
    assert e.args == {"a": 1}


def test_tool_call_text_is_args():
    e = parse_event({"session_id": "s", "kind": "tool_call", "tool": "http_post", "args": {"url": "http://x"}}, 0)
    assert "http://x" in e.text


def test_load_and_group(tmp_path):
    p = tmp_path / "t.jsonl"
    rows = [
        {"session_id": "b", "seq": 0, "ts": "2026-01-02T00:00:00Z", "kind": "user_message", "content": "later"},
        {"session_id": "a", "seq": 0, "ts": "2026-01-01T00:00:00Z", "kind": "user_message", "content": "earlier"},
        {"session_id": "a", "seq": 1, "ts": "2026-01-01T00:00:01Z", "kind": "model_output", "content": "ok"},
    ]
    p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    events = load_jsonl(str(p))
    assert len(events) == 3
    sessions = group_sessions(events)
    # session 'a' starts earlier, so it should come first
    assert [s.id for s in sessions] == ["a", "b"]
    assert [e.seq for e in sessions[0].events] == [0, 1]


def test_digest_stable():
    e = parse_event({"session_id": "s", "seq": 0, "kind": "user_message", "content": "x"}, 0)
    assert e.digest() == e.digest()
    assert len(e.digest()) == 64
