"""The evasion fuzzer encodes taintline's defense-in-depth guarantees as tests.

Single detection layers are evadable; the combination is not. These assertions
are the honest contract: hardening sharply improves the brittle layers, and the
behavioural layer plus the runtime guard hold against every synthetic variant,
including obfuscations that beat the injection regex.
"""

from taintline.fuzz import INJECTION_MUTATIONS, run_matrix, summarize


def test_defense_in_depth_holds_on_every_variant():
    results = run_matrix(hardened=True)
    assert results
    # the behavioural sequence layer (credential read -> unauthorized egress)
    # does not depend on phrasing or encoding, so it must catch everything
    assert all(r.seq for r in results), [r.as_dict() for r in results if not r.seq]
    # and at least one forensic layer fires for every variant
    assert all(r.any_high for r in results)
    # the runtime guard stops every variant before secret material leaves
    assert all(r.guard_stopped for r in results)


def test_hardening_improves_brittle_layers():
    base = summarize(run_matrix(hardened=False))
    hard = summarize(run_matrix(hardened=True))
    # obfuscation guts the injection + data-flow layers when hardening is off
    assert base["injection_layer_recall"] < 0.4
    assert base["data_flow_layer_recall"] <= 0.6
    # hardening recovers them
    assert hard["injection_layer_recall"] >= 0.8
    assert hard["data_flow_layer_recall"] >= 0.95


def test_paraphrase_evades_injection_regex_but_not_the_system():
    """Honest limitation: a pure semantic paraphrase has no trigger phrases, so
    the injection-text layer misses it - but the behavioural layer and guard do
    not, because they key off the *actions*, not the words."""
    from taintline.fuzz import run_variant

    r = run_variant("paraphrase", "plain", hardened=True)
    assert not r.inj  # no injection-phrase signal
    assert r.seq and r.any_high and r.guard_stopped  # still fully contained


def test_mutation_catalog_is_populated():
    assert len(INJECTION_MUTATIONS) >= 10
    assert "paraphrase" in INJECTION_MUTATIONS and "unicode_tags" in INJECTION_MUTATIONS
