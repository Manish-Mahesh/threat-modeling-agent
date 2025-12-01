"""
ThreatRelevanceAgent
Filters and matches threats and CVEs to the actual system architecture.
"""
from typing import List, Dict, Any
from tools.models import ArchitecturalThreat

class ThreatRelevanceAgent:
    """
    Matches generic threats and CVEs to the system, filtering out irrelevant ones.
    Output: list of relevant threats and CVEs with scores.
    """
    def match_relevant_threats(self, inferred_components: List[Dict[str, Any]], generic_threats: List[ArchitecturalThreat], cve_threats: List[Any]) -> Dict[str, Any]:
        # Build mappings of category -> list of component names for CVE matching
        category_to_components: Dict[str, List[str]] = {}
        for comp in inferred_components:
            name = comp.get("component_name")
            for cat in comp.get("inferred_product_categories", []):
                category_to_components.setdefault(cat, []).append(name)

        # Generic threats are already generated per-component by ThreatKnowledgeAgent
        # We just pass them through, potentially we could filter by severity here if needed.
        relevant_threats = generic_threats

        # Filter CVEs: ensure the CVE's affected_products maps to at least one identified component/product
        relevant_cves = []
        for cve in cve_threats:
            try:
                prod_field = getattr(cve, "affected_products", None)
                prod_text = str(prod_field).lower() if prod_field else ""

                # Match CVE to identified products or categories
                matched_components = []
                for cat, comps in category_to_components.items():
                    # Simple heuristic: if category name is in CVE product text
                    if cat.lower() in prod_text:
                        matched_components.extend(comps)

                # If the CVE text mentions any identified product string more precisely, include it
                if matched_components:
                    # Score: base 1.0, bump for production exposure if any component name contains 'production' or 'prod'
                    score = 1.0
                    if any('prod' in (c.lower() or '') for c in matched_components):
                        score = 1.2
                    relevant_cves.append({"cve": cve, "score": score, "affected_components": list(set(matched_components))})

            except Exception:
                continue

        return {
            "relevant_threats": relevant_threats,
            "relevant_cves": relevant_cves
        }
