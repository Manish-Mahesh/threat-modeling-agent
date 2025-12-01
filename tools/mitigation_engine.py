from typing import List, Optional
from tools.models import ThreatRecord, MitigationStrategy

# Common CWE Mappings to Mitigation Strategies
CWE_MITIGATIONS = {
    "CWE-89": {
        "primary_fix": "Use parameterized queries or prepared statements for all database interactions.",
        "configuration_changes": [],
        "access_control_changes": ["Ensure database accounts have least privilege (e.g., cannot drop tables)."],
        "monitoring_actions": ["Monitor database logs for SQL syntax errors or anomalous query patterns."],
        "additional_notes": ["Do not concatenate user input directly into SQL strings."]
    },
    "CWE-79": {
        "primary_fix": "Implement context-aware output encoding for all user-supplied data.",
        "configuration_changes": ["Implement Content Security Policy (CSP) headers."],
        "access_control_changes": [],
        "monitoring_actions": ["Monitor for reflected XSS payloads in web server logs."],
        "additional_notes": ["Validate input against a strict allowlist of expected formats."]
    },
    "CWE-20": {
        "primary_fix": "Implement strict input validation against a defined schema.",
        "configuration_changes": [],
        "access_control_changes": [],
        "monitoring_actions": ["Log all input validation failures."],
        "additional_notes": ["Reject any input that does not match the schema rather than attempting to sanitize it."]
    },
    "CWE-22": {
        "primary_fix": "Do not use user input directly in file system paths; use indirect object references.",
        "configuration_changes": ["Run the application with restricted file system permissions (chroot or container)."],
        "access_control_changes": [],
        "monitoring_actions": ["Monitor for file access attempts outside of expected directories."],
        "additional_notes": ["Verify the canonical path of the file is within the expected directory root."]
    },
    "CWE-352": {
        "primary_fix": "Implement anti-CSRF tokens for all state-changing requests.",
        "configuration_changes": ["Set SameSite cookie attribute to 'Strict' or 'Lax'."],
        "access_control_changes": [],
        "monitoring_actions": ["Monitor for requests with missing or invalid CSRF tokens."],
        "additional_notes": ["Ensure GET requests do not modify state."]
    },
    "CWE-287": {
        "primary_fix": "Enforce strong authentication mechanisms and disable default accounts.",
        "configuration_changes": ["Enforce Multi-Factor Authentication (MFA).", "Set strong password policies."],
        "access_control_changes": [],
        "monitoring_actions": ["Monitor for failed login attempts and brute-force patterns."],
        "additional_notes": []
    },
    "CWE-200": {
        "primary_fix": "Ensure sensitive information is not included in error messages or API responses.",
        "configuration_changes": ["Disable detailed error reporting in production.", "Strip sensitive headers (e.g., Server version)."],
        "access_control_changes": [],
        "monitoring_actions": [],
        "additional_notes": ["Review API responses to ensure no PII or internal system details are leaked."]
    }
}

def generate_mitigation(threat: ThreatRecord) -> MitigationStrategy:
    """
    Generates a detailed mitigation strategy based on CVSS vector and CWE.
    """
    
    # Initialize with defaults
    primary_fix = f"Update {threat.affected_products} to the latest version to resolve {threat.cve_id}."
    config_changes = []
    access_changes = []
    monitoring = []
    notes = ["Check the vendor's security advisory for specific patch instructions."]

    # 2. Analyze CVSS Vector for Context
    # Example Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    if threat.cvss_vector:
        vector_parts = threat.cvss_vector.split('/')
        av = next((p for p in vector_parts if p.startswith('AV:')), None) # Attack Vector
        
        if av == "AV:N":
            access_changes.append("Ensure the service is protected by a firewall and not exposed unnecessarily to the public internet.")
        elif av == "AV:L":
            access_changes.append("Ensure strict access controls are in place on the host machine (limit local users).")
        elif av == "AV:A":
            access_changes.append("Ensure network segmentation isolates this component from untrusted networks.")

    # 3. CWE Specific Guidance (Overrides or Augments)
    if threat.cwe_id:
        # Handle cases like "CWE-89" or just "89"
        cwe_key = threat.cwe_id if threat.cwe_id.startswith("CWE-") else f"CWE-{threat.cwe_id}"
        
        if cwe_key in CWE_MITIGATIONS:
            specific = CWE_MITIGATIONS[cwe_key]
            
            # If we have a specific primary fix (code change), we might append it or replace the generic patch message
            # Usually patching is still #1, but the code fix is important context.
            notes.append(f"Vulnerability Type: {specific['primary_fix']}")
            
            config_changes.extend(specific["configuration_changes"])
            access_changes.extend(specific["access_control_changes"])
            monitoring.extend(specific["monitoring_actions"])
            notes.extend(specific["additional_notes"])

    return MitigationStrategy(
        primary_fix=primary_fix,
        configuration_changes=config_changes,
        access_control_changes=access_changes,
        monitoring_actions=monitoring,
        additional_notes=notes
    )
