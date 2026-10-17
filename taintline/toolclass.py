"""Tool classification: which tools produce untrusted content (sources), which
perform sensitive actions (sinks), and which read secrets.

Classification is pattern based (fnmatch on the tool name) and can be extended
or overridden with a YAML file, see ``docs/rule-authoring.md``. Event metadata
can also force trust: ``meta.trust = "untrusted" | "trusted"``.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any

import yaml

from taintline.schema import Event

# source classes: where untrusted content can enter the model context
SOURCE_PATTERNS: dict[str, list[str]] = {
    "web": ["web_fetch", "fetch_url", "browse*", "browser_*", "http_get", "get_url", "scrape*", "curl", "visit*", "open_url", "read_webpage"],
    "search": ["web_search", "search*", "google*", "bing*", "duckduckgo*"],
    "email": ["read_email*", "gmail_*", "list_emails", "get_email*", "fetch_mail*", "outlook_*", "imap_*", "inbox*"],
    "chat_external": ["slack_read*", "slack_get*", "discord_*", "teams_read*", "read_messages", "get_channel*"],
    "document": ["read_pdf", "parse_document", "extract_text", "read_docx", "ocr*", "read_attachment*", "open_document"],
    "ticket": ["jira_get*", "github_get_issue*", "list_issues", "get_issue*", "read_ticket*", "zendesk_*", "get_pull_request*", "read_pr*"],
    "repo_external": ["clone_repo", "git_clone", "fetch_package*", "pip_show", "npm_view", "read_readme"],
}

SINK_PATTERNS: dict[str, list[str]] = {
    "network_egress": ["http_post", "http_put", "http_request", "post_url", "upload*", "webhook*", "curl_post", "send_request", "api_call", "fetch_post"],
    "email_send": ["send_email", "send_mail", "gmail_send", "reply_email", "forward_email", "smtp_*", "outlook_send"],
    "messaging_send": ["slack_post*", "slack_send*", "discord_send*", "teams_send*", "send_message", "post_message", "sms_send", "send_sms", "tweet", "post_tweet"],
    "code_execution": ["shell", "bash", "sh", "exec*", "run_command", "run_shell", "terminal", "subprocess", "python_exec", "run_code", "execute_code", "powershell", "cmd"],
    "file_write": ["write_file", "create_file", "save_file", "append_file", "edit_file", "fs_write", "put_file"],
    "destructive": ["delete*", "remove*", "rm", "drop_*", "truncate*", "purge*", "wipe*", "destroy*", "terminate*", "revoke*"],
    "cloud_control": ["aws_*", "iam_*", "gcp_*", "azure_*", "k8s_*", "kubectl*", "terraform_*", "cloud_*", "s3_put*", "ec2_*", "lambda_*", "create_access_key", "attach_policy", "assume_role"],
    "data_write": ["db_write", "sql_execute", "sql_write", "db_update", "db_insert", "update_record", "insert_record", "execute_sql", "run_query"],
    "financial": ["payment*", "transfer_funds", "send_payment", "stripe_*", "charge*", "wire*", "buy*", "sell*", "place_order"],
    "identity": ["create_user", "add_member", "grant_*", "set_password", "reset_password", "invite_user", "add_ssh_key", "add_deploy_key"],
}

SENSITIVE_READ_PATTERNS: dict[str, list[str]] = {
    "credential": ["read_secret*", "get_secret*", "get_credential*", "read_env", "get_env", "vault_*", "keychain_*", "aws_get_secret*", "secrets_*", "get_api_key", "list_api_keys", "get_token"],
    "pii": ["get_customer*", "list_customers", "get_user_profile", "export_users", "read_contacts", "list_contacts", "get_employee*"],
}

# file paths that mean "this read returned something sensitive"
SENSITIVE_PATH_HINTS = [
    "*.env", "*.env.*", "*/.env", "*id_rsa*", "*id_ed25519*", "*.pem", "*.key", "*/.aws/*", "*credentials*",
    "*/.ssh/*", "*.npmrc", "*.pypirc", "*/.docker/config.json", "*secrets*", "*token*", "*.kdbx", "*wallet*",
    "*/.netrc", "*.p12", "*.pfx", "*/.kube/config", "*service-account*.json", "*.tfvars",
]

# file paths that mean "this read returned content we did not author"
UNTRUSTED_PATH_HINTS = [
    "*/downloads/*", "*/download/*", "*/tmp/*", "*/temp/*", "*/attachments/*", "*/uploads/*", "*/inbox/*",
    "*/mnt/*", "*/shared/*", "*/external/*", "*/untrusted/*", "/dev/shm/*", "*.eml", "*.msg",
]

# a read_file-like tool
FILE_READ_PATTERNS = ["read_file", "cat", "open_file", "fs_read", "get_file", "view_file", "read_text", "load_file"]
MEMORY_WRITE_PATTERNS = ["memory_write", "save_memory", "remember", "store_memory", "update_memory", "set_memory"]
MEMORY_READ_PATTERNS = ["memory_read", "recall", "load_memory", "get_memory", "search_memory"]


@dataclass(frozen=True)
class ToolInfo:
    name: str
    source_class: str | None = None
    sink_class: str | None = None
    sensitive_class: str | None = None
    trust: str = "trusted"  # trusted | untrusted | unknown
    is_file_read: bool = False
    is_memory_write: bool = False
    is_memory_read: bool = False
    transport: str = "local"  # local | remote

    @property
    def is_source(self) -> bool:
        return self.source_class is not None

    @property
    def is_sink(self) -> bool:
        return self.sink_class is not None


def _match_any(name: str, patterns: list[str]) -> bool:
    low = name.lower()
    return any(fnmatch.fnmatchcase(low, p.lower()) for p in patterns)


def _first_match(name: str, table: dict[str, list[str]]) -> str | None:
    for cls, patterns in table.items():
        if _match_any(name, patterns):
            return cls
    return None


class ToolClassifier:
    def __init__(self, overrides: dict[str, Any] | None = None):
        self.sources = {k: list(v) for k, v in SOURCE_PATTERNS.items()}
        self.sinks = {k: list(v) for k, v in SINK_PATTERNS.items()}
        self.sensitive = {k: list(v) for k, v in SENSITIVE_READ_PATTERNS.items()}
        self.sensitive_paths = list(SENSITIVE_PATH_HINTS)
        self.untrusted_paths = list(UNTRUSTED_PATH_HINTS)
        self.trusted_tools: list[str] = []
        self.untrusted_tools: list[str] = []
        self.registered_remote: set[str] = set()
        if overrides:
            self.apply(overrides)

    @classmethod
    def from_yaml(cls, path: str) -> ToolClassifier:
        with open(path, encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh) or {})

    def apply(self, cfg: dict[str, Any]) -> None:
        for cls, pats in (cfg.get("sources") or {}).items():
            self.sources.setdefault(cls, []).extend(pats)
        for cls, pats in (cfg.get("sinks") or {}).items():
            self.sinks.setdefault(cls, []).extend(pats)
        for cls, pats in (cfg.get("sensitive_reads") or {}).items():
            self.sensitive.setdefault(cls, []).extend(pats)
        self.sensitive_paths.extend(cfg.get("sensitive_paths") or [])
        self.untrusted_paths.extend(cfg.get("untrusted_paths") or [])
        self.trusted_tools.extend(cfg.get("trusted_tools") or [])
        self.untrusted_tools.extend(cfg.get("untrusted_tools") or [])

    def note_registration(self, event: Event) -> None:
        """Record tool registrations so remote MCP tools are treated as egress sinks."""
        if event.kind == "tool_registered" and event.tool:
            transport = str(event.meta.get("transport", "local")).lower()
            if transport in ("remote", "http", "sse", "network"):
                self.registered_remote.add(event.tool.lower())

    def _path_of(self, event: Event) -> str:
        for key in ("path", "file", "filename", "filepath", "uri", "url", "src"):
            v = event.args.get(key)
            if isinstance(v, str):
                return v.replace("\\", "/")
        return ""

    def classify(self, event: Event) -> ToolInfo:
        name = (event.tool or "").strip()
        if not name:
            return ToolInfo(name="")
        low = name.lower()
        source = _first_match(name, self.sources)
        sink = _first_match(name, self.sinks)
        sensitive = _first_match(name, self.sensitive)
        is_file_read = _match_any(name, FILE_READ_PATTERNS)
        is_mem_w = _match_any(name, MEMORY_WRITE_PATTERNS)
        is_mem_r = _match_any(name, MEMORY_READ_PATTERNS)
        transport = "remote" if low in self.registered_remote or event.meta.get("transport") in ("remote", "http", "sse") else "local"

        path = self._path_of(event)
        if is_file_read and path:
            if _match_any(path, self.sensitive_paths):
                sensitive = sensitive or "credential"
            if _match_any(path, self.untrusted_paths):
                source = source or "file_external"
        # Any content pulled from a remote, unknown tool is untrusted input.
        if transport == "remote" and source is None and sink is None:
            source = "mcp_remote"
            sink = "mcp_remote"

        # Fetch / GET tools are a source (they bring content in) *and* an egress
        # channel (the request target and query string leave the trust boundary).
        # This is how GET-beacon and markdown-pixel exfiltration works.
        if source in ("web", "search") and sink is None:
            sink = "network_egress"

        trust = "trusted"
        if source is not None:
            trust = "untrusted"
        meta_trust = str(event.meta.get("trust", "")).lower()
        if _match_any(name, self.untrusted_tools) or meta_trust == "untrusted":
            trust = "untrusted"
            source = source or "untrusted_tool"
        if _match_any(name, self.trusted_tools) or meta_trust == "trusted":
            trust = "trusted"
            source = None

        return ToolInfo(
            name=name,
            source_class=source,
            sink_class=sink,
            sensitive_class=sensitive,
            trust=trust,
            is_file_read=is_file_read,
            is_memory_write=is_mem_w,
            is_memory_read=is_mem_r,
            transport=transport,
        )


# Sink classes ranked by how bad an attacker-controlled call to them is.
SINK_SEVERITY: dict[str, float] = {
    "financial": 1.0,
    "cloud_control": 1.0,
    "identity": 1.0,
    "code_execution": 0.95,
    "network_egress": 0.9,
    "email_send": 0.9,
    "messaging_send": 0.8,
    "mcp_remote": 0.8,
    "destructive": 0.85,
    "data_write": 0.7,
    "file_write": 0.45,
}

EXFIL_SINKS = {"network_egress", "email_send", "messaging_send", "mcp_remote"}
