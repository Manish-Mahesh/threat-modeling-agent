"""
ThreatKnowledgeAgent
Generates generic architectural threats using built-in threat patterns and STRIDE analysis.
"""
from typing import List, Dict, Any
from tools.models import ArchitecturalThreat, ArchitectureSchema

class ThreatKnowledgeAgent:
    """
    Produces generic architectural threats based on inferred component types and STRIDE analysis.
    """
    def generate_threats(self, inferred_components: List[Dict[str, Any]], architecture: ArchitectureSchema) -> List[ArchitecturalThreat]:
        threats = []
        
        # 1. Component-Based Threats (Existing Logic + STRIDE Mapping)
        for comp in inferred_components:
            comp_name = comp["component_name"]
            categories = comp["inferred_product_categories"]
            
            for category in categories:
                if category == "web_server":
                    threats.append(ArchitecturalThreat(
                        threat_id="T-WEB-01",
                        category="Spoofing",
                        description=f"Attacker may spoof the identity of the {comp_name} to intercept user traffic.",
                        affected_component=comp_name,
                        severity="High",
                        mitigation_steps=["Implement TLS/SSL", "Use strong server certificates"]
                    ))
                    threats.append(ArchitecturalThreat(
                        threat_id="T-WEB-02",
                        category="Denial of Service",
                        description=f"The {comp_name} may be subject to resource exhaustion attacks (DDoS).",
                        affected_component=comp_name,
                        severity="High",
                        mitigation_steps=["Implement rate limiting", "Use a WAF", "Configure resource quotas"]
                    ))
                elif category == "database":
                    threats.append(ArchitecturalThreat(
                        threat_id="T-DB-01",
                        category="Tampering",
                        description=f"Malicious SQL injection could tamper with data in {comp_name}.",
                        affected_component=comp_name,
                        affected_asset="Stored Data",
                        severity="Critical",
                        mitigation_steps=["Use parameterized queries", "Least privilege database accounts"]
                    ))
                    threats.append(ArchitecturalThreat(
                        threat_id="T-DB-02",
                        category="Information Disclosure",
                        description=f"Sensitive data in {comp_name} could be exposed via weak access controls or unencrypted storage.",
                        affected_component=comp_name,
                        affected_asset="Stored Data",
                        severity="Critical",
                        mitigation_steps=["Encrypt data at rest", "Implement strong ACLs"]
                    ))
                elif category == "cache":
                    threats.append(ArchitecturalThreat(
                        threat_id="T-CACHE-01",
                        category="Information Disclosure",
                        description=f"Cached data in {comp_name} might be accessible without authentication.",
                        affected_component=comp_name,
                        affected_asset="Cached Data",
                        severity="Medium",
                        mitigation_steps=["Require authentication for cache access", "Encrypt sensitive cached data"]
                    ))

        # 2. Trust Boundary Analysis
        # We need to look at the architecture schema to find boundaries
        # Since we don't have a full graph object here, we infer based on "Internet" or "External" mentions
        if architecture.trust_boundaries:
            for boundary in architecture.trust_boundaries:
                if "Internet" in boundary or "Public" in boundary:
                    threats.append(ArchitecturalThreat(
                        threat_id="T-NET-01",
                        category="Elevation of Privilege",
                        description=f"Attackers crossing the '{boundary}' boundary may attempt to elevate privileges.",
                        affected_component="Network Boundary",
                        trust_boundary=boundary,
                        severity="High",
                        mitigation_steps=["Implement DMZ", "Use Firewalls/WAF", "Zero Trust Architecture"]
                    ))

        # 3. Data Flow Analysis (Simple Heuristics)
        # If we had structured dataflows, we would iterate them. 
        # For now, we use the narrative if available or just general principles.
        if "database" in str(inferred_components).lower():
             threats.append(ArchitecturalThreat(
                threat_id="T-FLOW-01",
                category="Repudiation",
                description="Database transactions may lack sufficient logging to prove who performed an action.",
                affected_component="Database Transaction Logs",
                severity="Medium",
                mitigation_steps=["Enable comprehensive audit logging", "Secure log storage"]
            ))

        return threats
