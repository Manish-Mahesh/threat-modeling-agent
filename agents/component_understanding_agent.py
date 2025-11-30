"""
ComponentUnderstandingAgent
Infers real technology categories from raw architecture labels using heuristics and LLM reasoning.
"""
from typing import List, Dict, Any
import re
from tools.threat_intel_api import _looks_like_software_identifier

# Heuristic mapping for common generic labels to product families
GENERIC_TO_TECH = {
    "production server": ["linux", "web_server", "os"],
    "staging server": ["linux", "web_server", "os"],
    "development server": ["linux", "web_server", "os"],
    "developer computer": ["windows", "os", "developer_machine"],
    "content author computer": ["windows", "os", "developer_machine"],
    "automated deployment infrastructure": ["ci_cd", "pipeline"],
    "database": ["database"],
    "web server": ["web_server"],
    "ci/cd": ["ci_cd", "pipeline"],
    "cloud": ["cloud"],
}

# Simple confidence scoring
def score_confidence(label, inferred):
    if label.lower() in inferred:
        return 1.0
    if any(label.lower() in s for s in inferred):
        return 0.8
    return 0.6

class ComponentUnderstandingAgent:
    """
    Accepts raw component labels and infers likely technology categories.
    Output: list of dicts with component_name, inferred_product_categories, confidence
    """
    def infer_components(self, raw_labels: List[str]) -> List[Dict[str, Any]]:
        results = []
        for label in raw_labels:
            label_lower = label.lower().strip()
            inferred = []
            # Heuristic mapping
            for key, techs in GENERIC_TO_TECH.items():
                if key in label_lower:
                    inferred.extend(techs)
            # If label looks like a software identifier, add it
            if _looks_like_software_identifier(label):
                inferred.append(label_lower)
            # Remove duplicates
            inferred = list(set(inferred))
            confidence = score_confidence(label_lower, inferred)
            results.append({
                "component_name": label,
                "inferred_product_categories": inferred,
                "confidence": confidence
            })
        return results
