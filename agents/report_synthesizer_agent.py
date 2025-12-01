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
                "mitigation": cve["cve"].mitigation
            })
        return {
            "executive_summary": summary,
            "threat_landscape": landscape,
            "detailed_threat_list": threat_list,
            "prioritized_mitigations": mitigations
        }

    def generate_markdown_report(self, report_data: Dict[str, Any]) -> str:
        """
        Generates a Markdown formatted string from the report data.
        """
        md = []
        md.append("# 🛡️ Threat Model Report")
        md.append(f"**Date:** {self._get_current_date()}\n")
        
        md.append("## 📝 Executive Summary")
        md.append(report_data["executive_summary"] + "\n")
        
        md.append("## 🌍 High-level Threat Landscape")
        unique_landscape = sorted(list(set(report_data["threat_landscape"])))
        md.append(", ".join(unique_landscape) + "\n")
        
        md.append("## 🔥 Detailed Threat List")
        
        md.append("\n### Generic Architectural Threats")
        for item in report_data["detailed_threat_list"]:
            if "component_type" in item:
                md.append(f"\n#### 📌 {item['component_type'].upper()}")
                if item.get("affected_components"):
                    md.append(f"**Affected Components:** {', '.join(item['affected_components'])}")
                md.append("\n**Potential Threats:**")
                for t in item['threats']:
                    md.append(f"- {t}")

        md.append("\n### Specific Vulnerabilities (CVEs)")
        cves_found = False
        for item in report_data["detailed_threat_list"]:
            if "cve_id" in item:
                cves_found = True
                md.append(f"\n#### 🔴 {item['cve_id']}")
                md.append(f"**Severity:** {item['severity']} (Score: {item['score']})")
                if item.get("affected_components"):
                    md.append(f"**Affected Components:** {', '.join(item['affected_components'])}")
                md.append(f"\n> {item['summary']}")
        
        if not cves_found:
            md.append("\n*No specific CVEs found for the identified components.*")

        md.append("\n## 🛡️ Prioritized Mitigations")
        for mit in report_data["prioritized_mitigations"]:
            cve_id = mit['cve_id']
            strategy = mit['mitigation']
            
            md.append(f"\n### ✅ Mitigation for {cve_id}")
            
            if strategy:
                md.append(f"**Primary Fix:** {strategy.primary_fix}")
                
                if strategy.configuration_changes:
                    md.append("\n**Configuration Changes:**")
                    for change in strategy.configuration_changes:
                        md.append(f"- {change}")
                        
                if strategy.access_control_changes:
                    md.append("\n**Access Control Changes:**")
                    for change in strategy.access_control_changes:
                        md.append(f"- {change}")
                        
                if strategy.monitoring_actions:
                    md.append("\n**Monitoring Actions:**")
                    for action in strategy.monitoring_actions:
                        md.append(f"- {action}")
                        
                if strategy.additional_notes:
                    md.append("\n**Notes:**")
                    for note in strategy.additional_notes:
                        md.append(f"- {note}")
            else:
                md.append("Update or patch the affected product. Review vendor advisories.")
            
        return "\n".join(md)

    def _get_current_date(self) -> str:
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d")
