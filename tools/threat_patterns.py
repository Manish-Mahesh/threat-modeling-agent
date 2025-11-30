"""
threat_patterns.py
Built-in threat knowledge base for STRIDE, MITRE ATT&CK, CWE, and supply chain threats.
Maps threat categories to component types for use by the Threat Knowledge Agent.
"""

# STRIDE threat categories by component type
STRIDE_THREATS = {
    "database": ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"],
    "web_server": ["Spoofing", "Tampering", "Information Disclosure", "Denial of Service"],
    "ci_cd": ["Tampering", "Information Disclosure", "Elevation of Privilege", "Denial of Service"],
    "developer_machine": ["Information Disclosure", "Elevation of Privilege", "Malware Injection"],
    "cloud": ["Information Disclosure", "Denial of Service", "Elevation of Privilege", "Supply Chain Attack"],
    "os": ["Tampering", "Elevation of Privilege", "Denial of Service"],
    "runtime": ["Tampering", "Elevation of Privilege", "Denial of Service"],
    "pipeline": ["Tampering", "Information Disclosure", "Denial of Service", "Supply Chain Attack"],
}

# MITRE ATT&CK patterns (summaries only)
ATTACK_PATTERNS = {
    "database": ["Credential Access", "Data Exfiltration", "SQL Injection"],
    "web_server": ["Web Shell", "Remote Code Execution", "Directory Traversal"],
    "ci_cd": ["Pipeline Takeover", "Token Theft", "Build Poisoning"],
    "developer_machine": ["Credential Theft", "Malware Delivery", "Phishing"],
    "cloud": ["Account Hijacking", "Misconfiguration", "Privilege Escalation"],
    "os": ["Privilege Escalation", "Persistence", "Defense Evasion"],
    "runtime": ["Remote Code Execution", "Deserialization Attack"],
    "pipeline": ["Supply Chain Compromise", "Artifact Poisoning"],
}

# CWE categories relevant to software classes
CWE_CATEGORIES = {
    "database": ["CWE-89: SQL Injection", "CWE-200: Information Exposure", "CWE-284: Improper Access Control"],
    "web_server": ["CWE-79: XSS", "CWE-22: Path Traversal", "CWE-287: Improper Authentication"],
    "ci_cd": ["CWE-732: Incorrect Permission Assignment", "CWE-522: Insufficiently Protected Credentials"],
    "developer_machine": ["CWE-522: Insufficiently Protected Credentials", "CWE-255: Credentials Management Errors"],
    "cloud": ["CWE-798: Hardcoded Credentials", "CWE-287: Improper Authentication"],
    "os": ["CWE-264: Permissions, Privileges, and Access Controls", "CWE-269: Improper Privilege Management"],
    "runtime": ["CWE-502: Deserialization of Untrusted Data", "CWE-94: Code Injection"],
    "pipeline": ["CWE-829: Inclusion of Functionality from Untrusted Control Sphere"],
}

# Common pipeline, cloud, and supply chain attack scenarios
SUPPLY_CHAIN_ATTACKS = {
    "ci_cd": ["Malicious Dependency Injection", "Compromised Build Artifacts", "Pipeline Credential Theft"],
    "cloud": ["Third-party Service Compromise", "Cloud API Abuse"],
    "pipeline": ["Artifact Poisoning", "Dependency Confusion"],
}

# Generalized threat mappings by component type
THREAT_MAPPINGS = {
    "database": STRIDE_THREATS["database"] + ATTACK_PATTERNS["database"] + CWE_CATEGORIES["database"],
    "web_server": STRIDE_THREATS["web_server"] + ATTACK_PATTERNS["web_server"] + CWE_CATEGORIES["web_server"],
    "ci_cd": STRIDE_THREATS["ci_cd"] + ATTACK_PATTERNS["ci_cd"] + CWE_CATEGORIES["ci_cd"] + SUPPLY_CHAIN_ATTACKS["ci_cd"],
    "developer_machine": STRIDE_THREATS["developer_machine"] + ATTACK_PATTERNS["developer_machine"] + CWE_CATEGORIES["developer_machine"],
    "cloud": STRIDE_THREATS["cloud"] + ATTACK_PATTERNS["cloud"] + CWE_CATEGORIES["cloud"] + SUPPLY_CHAIN_ATTACKS["cloud"],
    "os": STRIDE_THREATS["os"] + ATTACK_PATTERNS["os"] + CWE_CATEGORIES["os"],
    "runtime": STRIDE_THREATS["runtime"] + ATTACK_PATTERNS["runtime"] + CWE_CATEGORIES["runtime"],
    "pipeline": STRIDE_THREATS["pipeline"] + ATTACK_PATTERNS["pipeline"] + CWE_CATEGORIES["pipeline"] + SUPPLY_CHAIN_ATTACKS["pipeline"],
}
