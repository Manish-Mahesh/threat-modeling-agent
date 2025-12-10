from typing import List, Optional, Dict
from tools.models import ThreatRecord, MitigationStrategy

# --- 1. Expanded CWE Mappings ---
CWE_MITIGATIONS = {
    # Injection & Input Validation
    "CWE-89": {
        "primary_fix": "Use parameterized queries or prepared statements.",
        "monitoring": ["Monitor database logs for SQL syntax errors."],
        "notes": ["Do not concatenate user input directly into SQL strings."],
        "nist": ["SI-10", "SA-8"]
    },
    "CWE-79": {
        "primary_fix": "Implement context-aware output encoding.",
        "config": ["Implement Content Security Policy (CSP) headers."],
        "monitoring": ["Monitor for reflected XSS payloads in web server logs."],
        "nist": ["SI-10", "SC-8"]
    },
    "CWE-20": {
        "primary_fix": "Implement strict input validation against a defined schema.",
        "monitoring": ["Log all input validation failures."],
        "notes": ["Reject any input that does not match the schema."],
        "nist": ["SI-10"]
    },
    "CWE-78": {
        "primary_fix": "Avoid invoking shell commands with user input.",
        "notes": ["Use language-specific APIs (e.g., subprocess.run with shell=False) instead of system()."],
        "nist": ["SI-10", "CM-7"]
    },
    "CWE-94": {
        "primary_fix": "Prevent code injection by disabling dynamic code evaluation features.",
        "config": ["Disable 'eval()' or similar functions in configuration."],
        "notes": ["Ensure user input is never passed to an interpreter."],
        "nist": ["SI-10", "CM-7"]
    },
    
    # Memory Safety (Buffer Overflows)
    "CWE-119": {
        "primary_fix": "Update to a patched version that fixes the memory corruption issue.",
        "config": ["Enable ASLR and DEP/NX on the host system."],
        "notes": ["This is a memory corruption vulnerability."],
        "nist": ["SI-16", "SC-39"]
    },
    "CWE-120": {
        "primary_fix": "Update to a patched version.",
        "notes": ["Classic Buffer Overflow."],
        "nist": ["SI-16"]
    },
    "CWE-122": {
        "primary_fix": "Update to a patched version.",
        "notes": ["Heap-based Buffer Overflow."],
        "nist": ["SI-16"]
    },
    "CWE-190": {
        "primary_fix": "Update to a patched version.",
        "notes": ["Integer Overflow leading to potential buffer overflow."],
        "nist": ["SI-16"]
    },
    
    # Access Control
    "CWE-284": {
        "primary_fix": "Enforce strict Access Control Lists (ACLs).",
        "access": ["Review and tighten permissions for the affected resource."],
        "notes": ["Ensure least privilege principle is applied."],
        "nist": ["AC-3", "AC-6"]
    },
    "CWE-266": {
        "primary_fix": "Review privilege assignment logic.",
        "access": ["Ensure users are not granted unintended privileges."],
        "notes": ["Privilege Isolation issue."],
        "nist": ["AC-6"]
    },
    "CWE-287": {
        "primary_fix": "Enforce strong authentication mechanisms.",
        "config": ["Enforce Multi-Factor Authentication (MFA)."],
        "monitoring": ["Monitor for failed login attempts."],
        "nist": ["IA-2", "IA-5"]
    },
    
    # Information Disclosure
    "CWE-200": {
        "primary_fix": "Ensure sensitive information is not included in error messages.",
        "config": ["Disable detailed error reporting in production."],
        "notes": ["Review API responses for PII leaks."],
        "nist": ["SC-8", "SI-11"]
    },
    
    # Resource Management
    "CWE-770": {
        "primary_fix": "Implement rate limiting and resource quotas.",
        "config": ["Configure connection limits and timeouts."],
        "monitoring": ["Monitor for resource exhaustion spikes."],
        "nist": ["SC-5"]
    },
    "CWE-400": {
        "primary_fix": "Implement resource consumption limits.",
        "config": ["Set limits on memory, CPU, and file descriptors per process."],
        "notes": ["Denial of Service via Resource Exhaustion."],
        "nist": ["SC-5"]
    },

    # Cryptographic Issues
    "CWE-319": {
        "primary_fix": "Enforce encryption in transit (TLS/SSL).",
        "config": ["Disable HTTP and Telnet; enforce HTTPS and SSH.", "Use strong cipher suites."],
        "monitoring": ["Monitor for unencrypted traffic on sensitive ports."],
        "nist": ["SC-8", "SC-13"]
    },
    "CWE-327": {
        "primary_fix": "Replace broken or risky cryptographic algorithms.",
        "config": ["Disable support for MD5, SHA1, RC4, and DES."],
        "notes": ["Use AES-256, RSA-2048+, or SHA-256+."],
        "nist": ["SC-13"]
    },
    "CWE-798": {
        "primary_fix": "Remove hardcoded credentials from code and config files.",
        "config": ["Use a Secrets Manager (Vault, AWS Secrets Manager, etc.)."],
        "monitoring": ["Scan codebase for high-entropy strings."],
        "nist": ["IA-5", "SC-28"]
    },

    # Server-Side Request Forgery (SSRF)
    "CWE-918": {
        "primary_fix": "Validate and sanitize all user-supplied URLs.",
        "config": ["Implement an allowlist of permitted domains/IPs.", "Disable HTTP redirects in the HTTP client."],
        "access": ["Block outbound traffic to internal metadata services (e.g., 169.254.169.254)."],
        "nist": ["AC-4", "SI-10"]
    },

    # XML External Entity (XXE)
    "CWE-611": {
        "primary_fix": "Disable DTD processing in XML parsers.",
        "config": ["Disallow DOCTYPE declarations.", "Disable external entity resolution."],
        "notes": ["If possible, switch to JSON or other simpler formats."],
        "nist": ["SI-10"]
    },

    # Insecure Deserialization
    "CWE-502": {
        "primary_fix": "Do not deserialize untrusted data.",
        "config": ["Use safe serialization formats like JSON instead of Pickle/Java Serialization."],
        "notes": ["If required, sign the data with a digital signature before deserialization."],
        "nist": ["SI-10"]
    },

    # Path Traversal
    "CWE-22": {
        "primary_fix": "Sanitize file path inputs to remove directory traversal characters (../).",
        "config": ["Run the service in a chroot jail or restricted container."],
        "notes": ["Use indirect object references (IDs) mapped to files instead of direct paths."],
        "nist": ["SI-10", "AC-6"]
    },

    # Missing Authentication/Authorization
    "CWE-306": {
        "primary_fix": "Require authentication for all critical functions.",
        "access": ["Implement a 'deny by default' access policy."],
        "nist": ["AC-3", "IA-2"]
    },
    "CWE-862": {
        "primary_fix": "Perform authorization checks for every actionable request.",
        "access": ["Verify that the authenticated user has permission to perform the requested action."],
        "nist": ["AC-3"]
    }
}

def _mitigate_redis(threat: ThreatRecord, summary_lower: str, steps: Dict[str, List[str]]):
    """Applies Redis-specific mitigation logic."""
    steps["config"].append("Ensure 'protected-mode' is set to 'yes'.")
    steps["config"].append("Bind Redis to localhost (127.0.0.1) if remote access is not strictly required.")
    steps["config"].append("Enable TLS and require client certificate authentication.")
    steps["nist"].extend(["SC-8", "AC-3"])
    
    # Dangerous Commands / Scripting
    if "lua" in summary_lower or "script" in summary_lower or "eval" in summary_lower:
        steps["access"].append("Restrict access to 'EVAL' and 'EVALSHA' commands using Redis ACLs.")
        steps["notes"].append("This vulnerability involves Lua scripting engine misuse.")
        steps["nist"].append("CM-7")
        
    # Configuration Abuse
    if "config set" in summary_lower or "configuration parameter" in summary_lower:
        steps["access"].append("Disable the 'CONFIG' command for unprivileged users via ACLs.")
        steps["notes"].append("Attackers may try to reconfigure Redis at runtime.")
        steps["nist"].append("CM-6")

    # Specific Parameters mentioned in CVEs
    if "proto-max-bulk-len" in summary_lower:
        steps["config"].append("Restrict 'proto-max-bulk-len' to a safe limit (e.g., 512MB) in redis.conf.")
    if "set-max-intset-entries" in summary_lower:
        steps["access"].append("Prevent modification of 'set-max-intset-entries' via ACL.")
    if "ziplist" in summary_lower:
        steps["access"].append("Prevent modification of ziplist configuration parameters via ACL.")
    if "hyperloglog" in summary_lower or "hll" in summary_lower:
        steps["access"].append("Restrict HyperLogLog commands if not used.")

def _mitigate_nginx(threat: ThreatRecord, summary_lower: str, steps: Dict[str, List[str]]):
    """Applies Nginx-specific mitigation logic."""
    steps["config"].append("Ensure Nginx worker processes run as a non-privileged user.")
    steps["config"].append("Implement WAF rules (e.g., ModSecurity) to block malicious payloads.")
    steps["nist"].extend(["AC-6", "SI-3"])
    
    # Modules
    if "mp4" in summary_lower or "ngx_http_mp4_module" in summary_lower:
        steps["config"].append("Disable the 'ngx_http_mp4_module' if video streaming is not required.")
        steps["nist"].append("CM-7")
    if "resolver" in summary_lower or "dns" in summary_lower:
        steps["config"].append("Restrict the 'resolver' directive to trusted internal DNS servers only.")
        steps["notes"].append("Avoid using public resolvers if processing untrusted input.")
        steps["nist"].append("SC-20")
    if "http/2" in summary_lower or "http2" in summary_lower:
        steps["config"].append("Ensure HTTP/2 is configured with safe limits (e.g., concurrent streams).")

def generate_mitigation(threat: ThreatRecord) -> MitigationStrategy:
    """
    Generates a detailed mitigation strategy based on CVSS vector, CWE, and Product Context.
    """
    
    # Container for collecting steps
    steps = {
        "primary": f"Update {threat.affected_products} to the latest version to resolve {threat.cve_id}.",
        "config": [],
        "access": [],
        "monitoring": [],
        "nist": ["SI-2"], # Flaw Remediation
        "notes": ["Check the vendor's security advisory for specific patch instructions."]
    }
    
    summary_lower = threat.summary.lower()
    
    # --- 1. Product-Specific Logic ---
    product_lower = threat.affected_products.lower()
    if "redis" in product_lower:
        _mitigate_redis(threat, summary_lower, steps)
    elif "nginx" in product_lower:
        _mitigate_nginx(threat, summary_lower, steps)

    # --- 2. CVSS Vector Analysis ---
    # Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    if threat.cvss_vector:
        vector_parts = threat.cvss_vector.split('/')
        
        # Attack Vector (AV)
        av = next((p for p in vector_parts if p.startswith('AV:')), None)
        if av == "AV:N": # Network
            steps["access"].append("Ensure the service is protected by a firewall and not exposed unnecessarily to the public internet.")
            steps["access"].append("Implement network segmentation to isolate this component.")
            steps["nist"].append("SC-7")
        elif av == "AV:L": # Local
            steps["access"].append("Ensure strict access controls are in place on the host machine (limit local users).")
            steps["config"].append("Apply OS-level hardening (e.g., SELinux/AppArmor).")
            steps["nist"].append("AC-3")
        elif av == "AV:A": # Adjacent
            steps["access"].append("Ensure the network segment is trusted and isolated from guest/public networks.")
            steps["nist"].append("SC-7")

        # Privileges Required (PR)
        pr = next((p for p in vector_parts if p.startswith('PR:')), None)
        if pr == "PR:N": # None
            steps["notes"].append("CRITICAL: This vulnerability requires NO authentication. Prioritize patching immediately.")
        
        # User Interaction (UI)
        ui = next((p for p in vector_parts if p.startswith('UI:')), None)
        if ui == "UI:N": # None
            steps["monitoring"].append("Automate vulnerability scanning as this can be exploited without user interaction.")
            steps["nist"].append("RA-5")

    # --- 3. CWE Specific Guidance ---
    if threat.cwe_id:
        cwe_key = threat.cwe_id if threat.cwe_id.startswith("CWE-") else f"CWE-{threat.cwe_id}"
        
        if cwe_key in CWE_MITIGATIONS:
            specific = CWE_MITIGATIONS[cwe_key]
            
            # Append specific guidance
            if "primary_fix" in specific:
                steps["notes"].append(f"Vulnerability Type: {specific['primary_fix']}")
            
            if "config" in specific:
                steps["config"].extend(specific["config"])
            if "access" in specific:
                steps["access"].extend(specific["access"])
            if "monitoring" in specific:
                steps["monitoring"].extend(specific["monitoring"])
            if "notes" in specific:
                steps["notes"].extend(specific["notes"])
            if "nist" in specific:
                steps["nist"].extend(specific["nist"])

    # Deduplicate lists
    return MitigationStrategy(
        primary_fix=steps["primary"],
        configuration_changes=list(set(steps["config"])),
        access_control_changes=list(set(steps["access"])),
        monitoring_actions=list(set(steps["monitoring"])),
        nist_controls=list(set(steps["nist"])),
        additional_notes=list(set(steps["notes"]))
    )
