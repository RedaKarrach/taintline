import json

from taintline.custody import build_manifest
from taintline.forensics import (
    assess_blast_radius,
    build_evidence_pack,
    extract_iocs,
    to_stix_bundle,
    verify_evidence_pack,
)
from taintline.forensics.pack import generate_keypair
from taintline.rules.engine import RuleEngine, load_rules
from taintline.schema import dump_jsonl, group_sessions, load_jsonl
from taintline.simulate.scenarios import SCENARIOS, get_scenario
from taintline.taint import TaintEngine
from taintline.toolclass import ToolClassifier


def _analyze(events):
    analyses = TaintEngine(ToolClassifier()).analyze_sessions(group_sessions(events))
    findings = RuleEngine(load_rules()).evaluate_all(analyses)
    return analyses, findings


def test_iocs_capture_exfil_endpoint_and_secret():
    analyses, _ = _analyze(get_scenario("indirect_exfil").build())
    iocs = extract_iocs(analyses)
    kinds = {(i.type, i.value) for i in iocs}
    assert ("domain", "evil-collector.test") in kinds
    assert any(i.type == "secret_exposed" and "aws" in i.value for i in iocs)
    # every IOC traces back to real events
    assert all(i.events for i in iocs)


def test_iocs_capture_poisoned_tool_and_memory():
    a_pois, _ = _analyze(get_scenario("tool_poisoning").build())
    assert any(i.type == "poisoned_tool" for i in extract_iocs(a_pois))
    events = get_scenario("memory_poison_write").build()
    assert any(i.type == "memory_key" for i in extract_iocs(_analyze(events)[0]))


def test_blast_radius_critical_for_credential_exfil():
    analyses, findings = _analyze(get_scenario("indirect_exfil").build())
    br = assess_blast_radius(analyses, findings, extract_iocs(analyses))
    assert br.tier == "critical"
    assert br.secrets_to_rotate and br.destinations_to_block
    assert any("Rotate" in s for s in br.remediation)
    assert br.stats["confirmed_egress"] is True


def test_blast_radius_flags_cross_session_and_persistence():
    events = get_scenario("memory_poison_write").build() + get_scenario("memory_poison_trigger").build()
    analyses, findings = _analyze(events)
    br = assess_blast_radius(analyses, findings, extract_iocs(analyses))
    assert br.cross_session is True
    assert any(p["kind"] == "poisoned_memory" for p in br.persistence)


def test_blast_radius_none_for_benign():
    analyses, findings = _analyze(get_scenario("benign_authorized_send").build())
    br = assess_blast_radius(analyses, findings, extract_iocs(analyses))
    assert br.tier == "none"
    assert not br.secrets_to_rotate


def test_stix_bundle_is_well_formed():
    analyses, findings = _analyze(get_scenario("cloud_privesc").build())
    bundle = to_stix_bundle(findings, extract_iocs(analyses))
    assert bundle["type"] == "bundle"
    types = {o["type"] for o in bundle["objects"]}
    assert "report" in types and "attack-pattern" in types
    # attack-patterns carry framework external references
    ap = next(o for o in bundle["objects"] if o["type"] == "attack-pattern")
    assert ap["external_references"]
    # deterministic ids: re-export is identical
    assert to_stix_bundle(findings, extract_iocs(analyses))["objects"][1]["id"] == bundle["objects"][1]["id"]
    # the whole thing round-trips as JSON
    json.loads(json.dumps(bundle))


def test_signed_evidence_pack_roundtrip(tmp_path):
    trace = tmp_path / "t.jsonl"
    dump_jsonl(get_scenario("indirect_exfil").build(), str(trace))
    events = load_jsonl(str(trace))
    analyses, findings = _analyze(events)
    iocs = extract_iocs(analyses)
    priv, pub = generate_keypair()
    pack = build_evidence_pack(
        build_manifest(str(trace), events),
        [f.to_dict() for f in findings],
        [i.to_dict() for i in iocs],
        assess_blast_radius(analyses, findings, iocs).to_dict(),
        to_stix_bundle(findings, iocs),
        private_pem=priv,
        public_pem=pub,
        case_id="CASE-001",
    )
    res = verify_evidence_pack(pack)
    assert res["ok"] and res["digest_ok"] and res["signature_ok"]
    # key pinning
    assert verify_evidence_pack(pack, expected_public_pem=pub)["key_matches_expected"] is True
    _, other_pub = generate_keypair()
    assert verify_evidence_pack(pack, expected_public_pem=other_pub)["ok"] is False


def test_tampered_pack_fails_verification():
    analyses, findings = _analyze(get_scenario("indirect_exfil").build())
    iocs = extract_iocs(analyses)
    priv, pub = generate_keypair()
    pack = build_evidence_pack({}, [f.to_dict() for f in findings], [i.to_dict() for i in iocs],
                               assess_blast_radius(analyses, findings, iocs).to_dict(),
                               to_stix_bundle(findings, iocs), private_pem=priv, public_pem=pub)
    assert verify_evidence_pack(pack)["ok"]
    # tamper with a finding after signing
    pack["body"]["findings"][0]["severity"] = "info"
    res = verify_evidence_pack(pack)
    assert not res["ok"] and res["digest_ok"] is False


def test_unsigned_pack_still_has_integrity_digest():
    analyses, findings = _analyze(get_scenario("pii_exfil").build())
    iocs = extract_iocs(analyses)
    pack = build_evidence_pack({}, [f.to_dict() for f in findings], [i.to_dict() for i in iocs],
                               assess_blast_radius(analyses, findings, iocs).to_dict(),
                               to_stix_bundle(findings, iocs))
    res = verify_evidence_pack(pack)
    assert res["digest_ok"] and res["signed"] is False and res["ok"]
