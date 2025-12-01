"""
ReportSynthesizerAgent
Combines relevant threats and CVEs into a final executive report following a strict 10-section format.
"""
from typing import Dict, Any, List
from datetime import datetime
from tools.models import ArchitectureSchema, ArchitecturalThreat, CVE, MitigationStrategy

class ReportSynthesizerAgent:
    """
    Synthesizes the final threat model report from relevant threats and CVEs.
    """
    def synthesize_report(self, match_results: Dict[str, Any], architecture: ArchitectureSchema) -> Dict[str, Any]:
        relevant_threats: List[ArchitecturalThreat] = match_results.get("relevant_threats", [])
        relevant_cves: List[Dict[str, Any]] = match_results.get("relevant_cves", [])
        
        # 1. Executive Summary
        high_severity_cves = [c for c in relevant_cves if c["cve"].severity in ["High", "Critical"]]
        summary = (
            f"This report presents a comprehensive threat model for the **{architecture.project_name}** system. "
            f"The analysis identified **{len(relevant_threats)} architectural threats** using the STRIDE methodology "
            f"and **{len(relevant_cves)} specific CVE vulnerabilities** affecting the technology stack. "
            f"Notably, **{len(high_severity_cves)} high/critical severity vulnerabilities** were detected that require immediate attention. "
            f"The report includes NIST 800-53 mapped controls for compliance and hardening."
        )

        # 2. Architecture Understanding
        arch_understanding = {
            "description": architecture.description,
            "components": [c.name for c in architecture.components],
            "data_flows": [f"{df.source} -> {df.destination} ({df.protocol})" for df in architecture.data_flows],
            "trust_boundaries": architecture.trust_boundaries
        }

        # 3. Asset Inventory
        assets = []
        for comp in architecture.components:
            assets.append({
                "name": comp.name,
                "type": comp.type,
                "criticality": "High" if "db" in comp.type or "database" in comp.type else "Medium" # Simple heuristic
            })

        return {
            "executive_summary": summary,
            "architecture": arch_understanding,
            "assets": assets,
            "threats": relevant_threats,
            "cves": relevant_cves,
            "project_name": architecture.project_name
        }

    def generate_markdown_report(self, report_data: Dict[str, Any]) -> str:
        """
        Generates a Markdown formatted string from the report data following the 10-section format.
        """
        md = []
        date_str = datetime.now().strftime("%Y-%m-%d")
        
        md.append(f"# 🛡️ Threat Model Report: {report_data['project_name']}")
        md.append(f"**Date:** {date_str}\n")
        
        # 1. Executive Summary
        md.append("## 1. Executive Summary")
        md.append(report_data["executive_summary"] + "\n")
        
        # 2. Architecture Understanding
        md.append("## 2. Architecture Understanding")
        arch = report_data["architecture"]
        md.append(f"**Description:** {arch['description']}\n")
        md.append("**Key Components:**")
        for c in arch['components']:
            md.append(f"- {c}")
        md.append("\n**Data Flows:**")
        for df in arch['data_flows']:
            md.append(f"- {df}")
        md.append("\n**Trust Boundaries:**")
        for tb in arch['trust_boundaries']:
            md.append(f"- {tb}")
        md.append("")

        # 3. Asset Inventory & Classification
        md.append("## 3. Asset Inventory & Classification")
        md.append("| Asset Name | Type | Criticality |")
        md.append("|---|---|---|")
        for asset in report_data["assets"]:
            md.append(f"| {asset['name']} | {asset['type']} | {asset['criticality']} |")
        md.append("")

        # 4. Threat Modeling Methodology (STRIDE)
        md.append("## 4. Threat Modeling Methodology")
        md.append("This assessment utilizes the **STRIDE** methodology to identify architectural threats:")
        md.append("- **S**poofing")
        md.append("- **T**ampering")
        md.append("- **R**epudiation")
        md.append("- **I**nformation Disclosure")
        md.append("- **D**enial of Service")
        md.append("- **E**levation of Privilege")
        md.append("\nVulnerabilities are analyzed using **CVSS v3.1** scoring and mapped to **NIST 800-53** controls.\n")

        # 5. Identified Threats & Vulnerabilities
        md.append("## 5. Identified Threats & Vulnerabilities")
        
        md.append("### 5.1 Architectural Threats (STRIDE)")
        threats: List[ArchitecturalThreat] = report_data["threats"]
        if not threats:
            md.append("*No architectural threats identified.*")
        else:
            for t in threats:
                md.append(f"#### {t.threat_id}: {t.category} - {t.affected_component}")
                md.append(f"- **Description:** {t.description}")
                md.append(f"- **Severity:** {t.severity}")
                if t.mitigation_steps:
                    md.append(f"- **Mitigation:** {', '.join(t.mitigation_steps)}")
                md.append("")

        md.append("### 5.2 Known Vulnerabilities (CVEs)")
        cves: List[Dict[str, Any]] = report_data["cves"]
        if not cves:
            md.append("*No specific CVEs identified.*")
        else:
            for item in cves:
                cve: CVE = item["cve"]
                md.append(f"#### {cve.cve_id} (CVSS: {cve.cvss_score})")
                md.append(f"- **Summary:** {cve.summary}")
                md.append(f"- **Severity:** {cve.severity}")
                md.append(f"- **Affected Component:** {', '.join(item.get('affected_components', []))}")
                md.append("")

        # 6. Attack Surface Analysis
        md.append("## 6. Attack Surface Analysis")
        md.append("The following entry points and interfaces represent the primary attack surface:")
        # Simple heuristic based on trust boundaries and web components
        md.append("- **Public Interfaces:** Web Servers, API Gateways (Inferred from architecture)")
        md.append("- **Network Boundaries:** " + ", ".join(arch['trust_boundaries']))
        md.append("")

        # 7. Risk Assessment
        md.append("## 7. Risk Assessment")
        md.append("Risk is calculated as **Likelihood x Impact**.")
        md.append("| Threat/CVE | Likelihood | Impact | Risk Level |")
        md.append("|---|---|---|---|")
        # Simplified risk table
        for t in threats:
            md.append(f"| {t.threat_id} | Medium | {t.severity} | {t.severity} |")
        for item in cves:
            cve = item["cve"]
            md.append(f"| {cve.cve_id} | High | {cve.severity} | {cve.severity} |")
        md.append("")

        # 8. Recommended Hardening Checklist (NIST 800-53)
        md.append("## 8. Recommended Hardening Checklist (NIST 800-53)")
        
        # Collect all mitigations
        all_mitigations = []
        for item in cves:
            cve: CVE = item["cve"]
            if cve.mitigation:
                all_mitigations.append(cve.mitigation)
        
        if not all_mitigations:
            md.append("*No specific hardening steps generated.*")
        else:
            for mit in all_mitigations:
                md.append(f"### Mitigation for {mit.primary_fix}") # Using primary fix as title if generic, or group by CVE
                if mit.nist_controls:
                    md.append(f"**NIST Controls:** {', '.join(mit.nist_controls)}")
                
                if mit.configuration_changes:
                    md.append("**Configuration:**")
                    for change in mit.configuration_changes:
                        md.append(f"- [ ] {change}")
                
                if mit.access_control_changes:
                    md.append("**Access Control:**")
                    for change in mit.access_control_changes:
                        md.append(f"- [ ] {change}")
                md.append("")

        # 9. Residual Risk Notes
        md.append("## 9. Residual Risk Notes")
        md.append("- **Zero-Day Attacks:** This model cannot account for unknown vulnerabilities.")
        md.append("- **Implementation Flaws:** Secure design does not guarantee secure implementation.")
        md.append("- **Third-Party Risk:** Dependencies may introduce risks not covered here.")
        md.append("")

        # 10. Conclusion
        md.append("## 10. Conclusion")
        md.append("The system architecture exhibits a mix of standard architectural risks and specific component vulnerabilities. ")
        md.append("Immediate priority should be given to patching high-severity CVEs and implementing the NIST-mapped controls outlined in Section 8.")
        
        return "\n".join(md)
