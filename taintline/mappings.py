"""Human-readable names for the framework identifiers used in rule mappings.

These labels are provided for report readability. Framework identifiers are
best-effort as of the taintline release date; verify against the live
framework before using them in a compliance submission.
"""

from __future__ import annotations

MITRE_ATLAS = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0020": "Poison Training Data / Persistent Data Poisoning",
}

MITRE_ATTACK = {
    "T1030": "Data Transfer Size Limits",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1083": "File and Directory Discovery",
    "T1098": "Account Manipulation",
    "T1485": "Data Destruction",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1552": "Unsecured Credentials",
    "T1567": "Exfiltration Over Web Service",
}

OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

NIST_AI_RMF = {
    "GOVERN 1.7": "Processes for decommissioning and phasing out AI systems",
    "GOVERN 6.1": "Policies address third-party AI risks (supply chain)",
    "MAP 4.1": "Approaches to map third-party technology risks",
    "MEASURE 2.7": "AI system security and resilience evaluated",
    "MANAGE 2.3": "Procedures to respond to and recover from incidents",
    "MANAGE 2.4": "Mechanisms to supersede, disengage or deactivate the system",
}

FRAMEWORKS = {
    "mitre_atlas": ("MITRE ATLAS", MITRE_ATLAS),
    "mitre_attack": ("MITRE ATT&CK", MITRE_ATTACK),
    "owasp_llm": ("OWASP Top 10 for LLM Applications (2025)", OWASP_LLM),
    "nist_ai_rmf": ("NIST AI RMF 1.0", NIST_AI_RMF),
}


def describe(framework: str, ident: str) -> str:
    _, table = FRAMEWORKS.get(framework, (framework, {}))
    name = table.get(ident)
    return f"{ident} ({name})" if name else ident


def framework_title(framework: str) -> str:
    return FRAMEWORKS.get(framework, (framework, {}))[0]
