"""taintline: forensic taint tracking and detection for AI agent tool-use traces."""

from taintline.schema import Event, Session, group_sessions, load_jsonl
from taintline.taint import SessionAnalysis, TaintEngine

__version__ = "0.1.0"

__all__ = [
    "Event",
    "Session",
    "SessionAnalysis",
    "TaintEngine",
    "group_sessions",
    "load_jsonl",
    "__version__",
]
