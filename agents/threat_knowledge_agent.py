"""
ThreatKnowledgeAgent
Generates generic architectural threats using built-in threat patterns.
"""
from typing import List, Dict, Any
from tools.threat_patterns import THREAT_MAPPINGS

class ThreatKnowledgeAgent:
    """
    Produces generic architectural threats based on inferred component types.
    Output: list of dicts with component_type, threats
    """
    def generate_threats(self, inferred_components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        threats = []
        for comp in inferred_components:
            for category in comp["inferred_product_categories"]:
                if category in THREAT_MAPPINGS:
                    threats.append({
                        "component_type": category,
                        "threats": THREAT_MAPPINGS[category]
                    })
        return threats
