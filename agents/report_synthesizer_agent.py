"""
ReportSynthesizerAgent
Combines relevant threats and CVEs into a final executive report.
"""
from typing import Dict, Any

class ReportSynthesizerAgent:
    """
    Synthesizes the final threat model report from relevant threats and CVEs.
    Output: dict with executive summary, threat landscape, detailed threat list, prioritized mitigations.
    """
    def synthesize_report(self, match_results: Dict[str, Any]) -> Dict[str, Any]:
        relevant_threats = match_results["relevant_threats"]
        relevant_cves = match_results["relevant_cves"]
        # Executive Summary
        summary = (
            f"This report summarizes the threat modeling analysis. "
            f"We identified {len(relevant_threats)} generic architectural threat categories "
            f"and {len(relevant_cves)} specific CVE vulnerabilities applicable to the system's technology stack. "
            f"Focus has been placed on high-severity issues affecting production and critical infrastructure."
        )
        # Threat Landscape
        landscape = [t["component_type"] for t in relevant_threats]
        # Detailed Threat List
        threat_list = []
        for t in relevant_threats:
            threat_list.append({
                "component_type": t["component_type"],
                "threats": t["threats"],
                "affected_components": t.get("affected_components", [])
            })
        for cve in relevant_cves:
            threat_list.append({
                "cve_id": cve["cve"].cve_id,
                "summary": cve["cve"].summary,
                "severity": cve["cve"].severity,
                "score": cve["score"],
                "affected_components": cve.get("affected_components", [])
            })
        # Prioritized Mitigations
        mitigations = []
        for cve in relevant_cves:
            mitigations.append({
                "cve_id": cve["cve"].cve_id,
                "mitigation": "Update or patch the affected product. Review vendor advisories."
            })
        return {
            "executive_summary": summary,
            "threat_landscape": landscape,
            "detailed_threat_list": threat_list,
            "prioritized_mitigations": mitigations
        }
