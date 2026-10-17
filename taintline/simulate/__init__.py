"""Synthetic trace generation: benign baselines and labelled attack scenarios.

Everything here is *fabricated* data for testing the detector. No real systems
are touched. Secrets are obviously fake (``AKIAFAKE...``) and destinations use
RFC 2606 reserved domains (``example.com``) or ``evil-collector.test``.
"""

from taintline.simulate.scenarios import ATTACK_SCENARIOS, SCENARIOS, build_dataset, get_scenario
from taintline.simulate.synth import benign_session, make_builder

__all__ = [
    "ATTACK_SCENARIOS",
    "SCENARIOS",
    "benign_session",
    "build_dataset",
    "get_scenario",
    "make_builder",
]
