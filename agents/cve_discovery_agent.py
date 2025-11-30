"""
CVEDiscoveryAgent
Queries NVD/CISA KEV for inferred product categories only.
"""
from typing import List, Dict, Any
from tools.threat_intel_api import search_vulnerabilities, _looks_like_software_identifier, GENERIC_LABELS

class CVEDiscoveryAgent:
    """
    Queries NVD/CISA KEV for high/critical CVEs for inferred product categories.
    Output: list of ThreatRecord objects (raw CVEs)
    """
    def discover_cves(self, inferred_components: List[Dict[str, Any]]) -> List[Any]:
        # Collect specific product identifiers (avoid generic categories like 'linux', 'os', 'web_server')
        product_identifiers = set()
        for comp in inferred_components:
            for category in comp["inferred_product_categories"]:
                cat_lower = category.lower()
                if cat_lower in GENERIC_LABELS:
                    continue
                # Use _looks_like_software_identifier to further validate
                if _looks_like_software_identifier(category):
                    product_identifiers.add(category)

        if not product_identifiers:
            print("No concrete product identifiers found in inferred components; skipping NVD/CVE discovery.")
            return []

        # Call the search with the concrete product identifiers
        return search_vulnerabilities(None, list(product_identifiers)).threats
