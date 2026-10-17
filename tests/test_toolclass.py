from taintline.schema import parse_event
from taintline.toolclass import ToolClassifier


def _call(tool, **args):
    return parse_event({"session_id": "s", "kind": "tool_call", "tool": tool, "args": args}, 0)


def _result(tool, content, **meta):
    return parse_event({"session_id": "s", "kind": "tool_result", "tool": tool, "content": content, "meta": meta}, 0)


def test_source_classification():
    c = ToolClassifier()
    assert c.classify(_result("web_fetch", "x")).source_class == "web"
    assert c.classify(_result("read_email", "x")).source_class == "email"


def test_sink_classification():
    c = ToolClassifier()
    assert c.classify(_call("http_post", url="http://x")).sink_class == "network_egress"
    assert c.classify(_call("send_email", to="a@b.c")).sink_class == "email_send"
    assert c.classify(_call("delete_object", key="x")).sink_class == "destructive"
    assert c.classify(_call("iam_attach_policy", user="x")).sink_class == "cloud_control"


def test_sensitive_read_by_path():
    c = ToolClassifier()
    info = c.classify(_call("read_file", path="/home/u/.aws/credentials"))
    assert info.sensitive_class == "credential"


def test_untrusted_path_is_source():
    c = ToolClassifier()
    info = c.classify(_call("read_file", path="/home/u/downloads/sketchy.txt"))
    assert info.source_class is not None


def test_remote_mcp_is_source_and_sink():
    c = ToolClassifier()
    reg = parse_event({"session_id": "s", "kind": "tool_registered", "tool": "mcp_weird", "meta": {"transport": "remote"}}, 0)
    c.note_registration(reg)
    info = c.classify(_call("mcp_weird", x=1))
    assert info.transport == "remote"
    assert info.sink_class == "mcp_remote"


def test_meta_trust_override():
    c = ToolClassifier()
    info = c.classify(_result("web_fetch", "x", trust="trusted"))
    assert info.source_class is None
