import os
import requests
from google.adk.tools import ToolContext
from tools.models import ThreatRecord, ThreatSearchResults # Import the Pydantic schemas

# NOTE: The 'nvdlib' library is the simplest way to interface with the NVD API.
# You must install it: pip install nvdlib
try:
    import nvdlib
except ImportError:
    print("WARNING: nvdlib is not installed. Threat intelligence tool will not function.")

# CISA KEV Catalog JSON feed URL (Authoritative source for actively exploited vulnerabilities)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# NVD API Key (Highly Recommended for production to increase rate limits)
NVD_API_KEY = os.getenv("NVD_API_KEY") 

def _fetch_kev_cve_ids() -> set[str]:
    """Internal helper to fetch the set of CVE IDs in the CISA KEV catalog."""
    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        # Extract only the CVE IDs from the KEV list for fast lookup
        return {item['cveID'] for item in response.json().get('vulnerabilities', [])}
    except Exception as e:
        print(f"Error fetching CISA KEV data: {e}")
        return set()


from functools import lru_cache

@lru_cache(maxsize=1)
def _fetch_kev_cve_ids_cached() -> set[str]:
    return _fetch_kev_cve_ids()



def search_vulnerabilities(tool_context: ToolContext, components: list[Component]) -> ThreatSearchResults:
    kev_cve_ids = _fetch_kev_cve_ids_cached()
    found: dict[str, ThreatRecord] = {}

    for comp in components:
        query = f"{comp.name} {comp.version or ''}".strip()
        if not query:
            continue

        try:
            results = nvdlib.searchCVE(
                keywordSearch=query,
                cvssV3Severity='HIGH',
                limit=10,
                key=NVD_API_KEY,
            )
        except Exception as e:
            print(f"Error searching NVD for {query}: {e}")
            continue

        for cve in results:
            cve_id = cve.id
            if cve_id in found:
                continue

            summary = cve.descriptions[0].value if cve.descriptions else "No summary available."
            severity = "N/A"
            if cve.metrics:
                if hasattr(cve.metrics, "cvssMetricV31"):
                    severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity
                elif hasattr(cve.metrics, "cvssMetricV30"):
                    severity = cve.metrics.cvssMetricV30[0].cvssData.baseSeverity

            found[cve_id] = ThreatRecord(
                cve_id=cve_id,
                summary=summary,
                severity=severity,
                affected_products=f"{comp.name} {comp.version or ''} ({comp.environment})",
                is_actively_exploited=cve_id in kev_cve_ids,
                source="NVD/CISA KEV",
            )

    return ThreatSearchResults(threats=list(found.values()))
