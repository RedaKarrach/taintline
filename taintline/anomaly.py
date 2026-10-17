"""Behavioural anomaly scoring for sessions.

Two complementary signals:

1. A bigram Markov model over the sequence of tool classes, trained on a benign
   baseline. Sessions whose tool-call grammar is unlikely under the baseline get
   a high negative log-likelihood.
2. An Isolation Forest over session-level features (counts, ratios, entropy,
   secret hits, taint density, the Markov NLL itself).

The forest is implemented here in ~80 lines of numpy and **serialised as plain
JSON**. A security tool that loads a pickled model is a deserialisation RCE
waiting to happen; taintline never pickles.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any

import numpy as np

from taintline.taint import SessionAnalysis

FEATURE_NAMES = [
    "n_events",
    "n_tool_calls",
    "n_unique_tools",
    "sink_ratio",
    "source_ratio",
    "exfil_calls",
    "destructive_calls",
    "credential_reads",
    "max_same_tool_run",
    "tool_entropy",
    "mean_args_len",
    "max_args_len",
    "secret_hits",
    "max_injection_score",
    "tainted_call_ratio",
    "max_flow_confidence",
    "unauthorized_dest_calls",
    "markov_nll",
]

# Relative emphasis per feature for the (standardized) isolation forest. Security
# -salient signals are weighted up so they are not drowned out by high-variance
# structural features. Purely a detection-tuning knob; it changes ranking, not
# the feature values reported to the analyst.
FEATURE_WEIGHTS = {
    "exfil_calls": 2.0,
    "destructive_calls": 1.5,
    "credential_reads": 1.5,
    "secret_hits": 2.5,
    "max_injection_score": 2.5,
    "tainted_call_ratio": 2.0,
    "max_flow_confidence": 3.0,
    "unauthorized_dest_calls": 2.5,
    "markov_nll": 1.5,
}

EULER = 0.5772156649


def _tool_token(a: SessionAnalysis, e: Any) -> str:
    info = a.info(e)
    if e.kind != "tool_call":
        return e.kind
    cls = info.sink_class or info.sensitive_class or info.source_class
    return f"call:{cls or 'other'}"


def token_sequence(a: SessionAnalysis) -> list[str]:
    return ["<s>"] + [_tool_token(a, e) for e in a.events] + ["</s>"]


# ---------------------------------------------------------------------------
# Markov bigram model
# ---------------------------------------------------------------------------


class BigramModel:
    def __init__(self, counts: dict[str, dict[str, int]] | None = None, vocab: list[str] | None = None):
        self.counts: dict[str, dict[str, int]] = counts or {}
        self.vocab: set[str] = set(vocab or [])

    def fit(self, sequences: list[list[str]]) -> BigramModel:
        for seq in sequences:
            for u, v in zip(seq, seq[1:], strict=False):
                self.counts.setdefault(u, {})
                self.counts[u][v] = self.counts[u].get(v, 0) + 1
                self.vocab.update((u, v))
        return self

    def nll(self, seq: list[str]) -> float:
        """Mean negative log-likelihood per transition with add-one smoothing."""
        if len(seq) < 2:
            return 0.0
        V = max(1, len(self.vocab)) + 1
        total = 0.0
        for u, v in zip(seq, seq[1:], strict=False):
            row = self.counts.get(u, {})
            denom = sum(row.values()) + V
            total += -math.log((row.get(v, 0) + 1) / denom)
        return total / (len(seq) - 1)

    def to_dict(self) -> dict[str, Any]:
        return {"counts": self.counts, "vocab": sorted(self.vocab)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> BigramModel:
        return cls(counts=d.get("counts", {}), vocab=d.get("vocab", []))


# ---------------------------------------------------------------------------
# features
# ---------------------------------------------------------------------------


def session_features(a: SessionAnalysis, bigram: BigramModel | None) -> np.ndarray:
    events = a.events
    calls = [e for e in events if e.kind == "tool_call"]
    results = [e for e in events if e.kind == "tool_result"]
    n_calls = len(calls)
    infos = [a.info(e) for e in calls]
    sinks = sum(1 for i in infos if i.is_sink)
    sources = sum(1 for e in results if a.info(e).is_source)
    exfil = sum(1 for i in infos if i.sink_class in ("network_egress", "email_send", "messaging_send", "mcp_remote"))
    destructive = sum(1 for i in infos if i.sink_class == "destructive")
    cred = sum(1 for i in infos if i.sensitive_class == "credential")
    # longest run of the same tool
    best = run = 0
    prev = None
    for e in calls:
        run = run + 1 if e.tool == prev else 1
        prev = e.tool
        best = max(best, run)
    # entropy of tool usage
    freq: dict[str, int] = {}
    for e in calls:
        freq[e.tool or ""] = freq.get(e.tool or "", 0) + 1
    entropy = -sum((c / n_calls) * math.log2(c / n_calls) for c in freq.values()) if n_calls else 0.0
    arg_lens = [len(e.args_text) for e in calls] or [0]
    secret_hits = sum(len(v) for v in a.secrets.values())
    max_inj = max((s.score for s in a.injection.values()), default=0.0)
    tainted_calls = sum(1 for e in calls if a.taints.get(e.id))
    max_flow = max((f.confidence for f in a.flows), default=0.0)
    unauth = sum(1 for f in a.flows if f.details.get("destinations") and not f.details.get("destination_authorized"))
    nll = bigram.nll(token_sequence(a)) if bigram else 0.0
    return np.array(
        [
            len(events),
            n_calls,
            len(freq),
            sinks / n_calls if n_calls else 0.0,
            sources / max(1, len(results)),
            exfil,
            destructive,
            cred,
            best,
            entropy,
            float(np.mean(arg_lens)),
            float(np.max(arg_lens)),
            secret_hits,
            max_inj,
            tainted_calls / n_calls if n_calls else 0.0,
            max_flow,
            unauth,
            nll,
        ],
        dtype=float,
    )


# ---------------------------------------------------------------------------
# JSON-serialisable isolation forest
# ---------------------------------------------------------------------------


def _c(n: float) -> float:
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + EULER) - 2.0 * (n - 1) / n


def _build_tree(X: np.ndarray, idx: np.ndarray, depth: int, max_depth: int, rng: np.random.Generator) -> dict[str, Any]:
    if depth >= max_depth or len(idx) <= 1:
        return {"n": int(len(idx))}
    sub = X[idx]
    lo = sub.min(axis=0)
    hi = sub.max(axis=0)
    usable = np.where(hi > lo)[0]
    if len(usable) == 0:
        return {"n": int(len(idx))}
    f = int(rng.choice(usable))
    split = float(rng.uniform(lo[f], hi[f]))
    left = idx[sub[:, f] < split]
    right = idx[sub[:, f] >= split]
    if len(left) == 0 or len(right) == 0:
        return {"n": int(len(idx))}
    return {
        "f": f,
        "s": split,
        "l": _build_tree(X, left, depth + 1, max_depth, rng),
        "r": _build_tree(X, right, depth + 1, max_depth, rng),
    }


def _path_len(x: np.ndarray, node: dict[str, Any], depth: int = 0) -> float:
    if "f" not in node:
        return depth + _c(node["n"])
    if x[node["f"]] < node["s"]:
        return _path_len(x, node["l"], depth + 1)
    return _path_len(x, node["r"], depth + 1)


class IsolationForest:
    def __init__(self, n_trees: int = 100, sample_size: int = 256, seed: int = 7):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.seed = seed
        self.trees: list[dict[str, Any]] = []
        self.effective_sample = sample_size

    def fit(self, X: np.ndarray) -> IsolationForest:
        rng = np.random.default_rng(self.seed)
        n = len(X)
        self.effective_sample = min(self.sample_size, n)
        max_depth = int(math.ceil(math.log2(max(2, self.effective_sample))))
        self.trees = []
        for _ in range(self.n_trees):
            idx = rng.choice(n, size=self.effective_sample, replace=False)
            self.trees.append(_build_tree(X, idx, 0, max_depth, rng))
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        if not self.trees:
            raise RuntimeError("forest not fitted")
        c = _c(self.effective_sample) or 1.0
        out = np.empty(len(X))
        for i, x in enumerate(X):
            mean_path = float(np.mean([_path_len(x, t) for t in self.trees]))
            out[i] = 2.0 ** (-mean_path / c)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "n_trees": self.n_trees,
            "sample_size": self.sample_size,
            "effective_sample": self.effective_sample,
            "seed": self.seed,
            "trees": self.trees,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> IsolationForest:
        f = cls(n_trees=d["n_trees"], sample_size=d["sample_size"], seed=d.get("seed", 7))
        f.trees = d["trees"]
        f.effective_sample = d.get("effective_sample", d["sample_size"])
        return f


# ---------------------------------------------------------------------------
# baseline bundle
# ---------------------------------------------------------------------------


@dataclass
class AnomalyResult:
    session_id: str
    score: float
    is_anomalous: bool
    markov_nll: float
    top_features: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "score": round(self.score, 4),
            "is_anomalous": self.is_anomalous,
            "markov_nll": round(self.markov_nll, 4),
            "top_features": self.top_features,
        }


class Baseline:
    VERSION = 1

    def __init__(self) -> None:
        self.bigram = BigramModel()
        self.forest = IsolationForest()
        self.mean = np.zeros(len(FEATURE_NAMES))
        self.std = np.ones(len(FEATURE_NAMES))
        self.weights = np.array([FEATURE_WEIGHTS.get(n, 1.0) for n in FEATURE_NAMES], dtype=float)
        self.threshold = 0.6
        self.n_sessions = 0

    def _standardize(self, X: np.ndarray) -> np.ndarray:
        # Robust scaling plus a modest emphasis on security-salient features so
        # the isolation forest's uniform split selection does not get swamped by
        # high-magnitude structural columns (argument lengths, event counts).
        Z = (X - self.mean) / self.std
        return Z * self.weights

    def fit(self, analyses: list[SessionAnalysis], contamination_quantile: float = 0.99) -> Baseline:
        if len(analyses) < 5:
            raise ValueError("need at least 5 benign sessions to build a baseline")
        self.bigram = BigramModel().fit([token_sequence(a) for a in analyses])
        X = np.vstack([session_features(a, self.bigram) for a in analyses])
        self.mean = X.mean(axis=0)
        self.std = X.std(axis=0)
        self.std[self.std == 0] = 1.0
        Z = self._standardize(X)
        self.forest = IsolationForest(sample_size=min(256, len(Z))).fit(Z)
        scores = self.forest.score(Z)
        self.threshold = float(max(0.5, np.quantile(scores, contamination_quantile)))
        self.n_sessions = len(X)
        return self

    def score(self, a: SessionAnalysis) -> AnomalyResult:
        x = session_features(a, self.bigram)
        s = float(self.forest.score(self._standardize(x[None, :]))[0])
        z = (x - self.mean) / self.std
        order = np.argsort(-np.abs(z))[:4]
        top = [
            {"feature": FEATURE_NAMES[i], "value": round(float(x[i]), 3), "baseline_mean": round(float(self.mean[i]), 3), "z": round(float(z[i]), 2)}
            for i in order
            if abs(z[i]) >= 1.0
        ]
        return AnomalyResult(a.session.id, s, s >= self.threshold, float(x[-1]), top)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.VERSION,
            "features": FEATURE_NAMES,
            "mean": self.mean.tolist(),
            "std": self.std.tolist(),
            "threshold": self.threshold,
            "n_sessions": self.n_sessions,
            "bigram": self.bigram.to_dict(),
            "forest": self.forest.to_dict(),
        }

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh)

    @classmethod
    def load(cls, path: str) -> Baseline:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        if d.get("version") != cls.VERSION:
            raise ValueError(f"unsupported baseline version {d.get('version')}")
        if d.get("features") != FEATURE_NAMES:
            raise ValueError("baseline was built with a different feature set; rebuild it")
        b = cls()
        b.mean = np.array(d["mean"], dtype=float)
        b.std = np.array(d["std"], dtype=float)
        b.threshold = float(d["threshold"])
        b.n_sessions = int(d.get("n_sessions", 0))
        b.bigram = BigramModel.from_dict(d["bigram"])
        b.forest = IsolationForest.from_dict(d["forest"])
        return b
