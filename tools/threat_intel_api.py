import os
import re
import requests
from functools import lru_cache
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

# Heuristic sets for filtering generic terms
GENERIC_LABELS = {
    "staging", "production", "prod", "dev", "development", "test", "qa", "uat",
    "server", "computer", "workstation", "laptop", "pc", "infrastructure",
    "environment", "node", "host", "author", "content", "developer", "client",
    "user", "content author computer", "automated deployment infrastructure",
    # High-level inferred categories that must not trigger NVD queries on their own
    "windows", "linux", "os", "web_server", "ci_cd", "pipeline", "developer_machine"
}

KNOWN_TECH = {
    "nginx", "apache", "django", "laravel", "node", "postgres", "mysql", "redis",
    "kubernetes", "docker", "jenkins", "gitlab", "ubuntu", "windows",
    "python", "java", "javascript", "typescript", "c++", "c#", "go", "rust", "ruby",
    "php", "swift", "kotlin", "scala", "perl", "bash", "shell", "powershell", "sql",
    "nosql", "mongodb", "mongo", "cassandra", "elasticsearch", "elastic", "kibana",
    "logstash", "kafka", "rabbitmq", "activemq", "zeromq", "tomcat", "jetty", "express",
    "react", "angular", "vue", "svelte", "nextjs", "nuxtjs", "gatsby", "flask", "fastapi",
    "spring", "boot", "hibernate", "jpa", "dotnet", "aspnet", "core", "mvc", "entity",
    "framework", "symfony", "rails", "sinatra", "phoenix", "elixir", "flutter",
    "react-native", "ionic", "cordova", "electron", "qt", "gtk", "wxwidgets", "aws",
    "azure", "gcp", "google", "cloud", "amazon", "microsoft", "oracle", "ibm", "salesforce",
    "heroku", "digitalocean", "linode", "vultr", "helm", "terraform", "ansible", "chef",
    "puppet", "salt", "github", "bitbucket", "circleci", "travis", "teamcity", "bamboo",
    "jira", "confluence", "trello", "slack", "discord", "zoom", "teams", "skype",
    "whatsapp", "telegram", "signal", "debian", "centos", "rhel", "fedora", "alpine",
    "arch", "gentoo", "macos", "android", "ios", "chrome", "firefox", "safari", "edge",
    "opera", "brave", "tor", "vpn", "dns", "http", "https", "tcp", "udp", "ip", "ipv4",
    "ipv6", "ssh", "ftp", "sftp", "smtp", "imap", "pop3", "ldap", "kerberos", "oauth",
    "openid", "jwt", "saml", "tls", "ssl", "rsa", "aes", "sha", "md5", "bcrypt", "scrypt",
    "argon2", "wordpress", "drupal", "joomla", "magento", "shopify", "woocommerce",
    "prestashop"
}

VERSION_PATTERN = re.compile(r'\d+(\.\d+)+')

def _looks_like_software_identifier(name: str) -> bool:
    """
    Heuristic to detect if a string looks like a real software product name 
    rather than a generic architecture label.
    """
    name_lower = name.lower().strip()
    
    # 1. Check if the exact name is in the generic set
    if name_lower in GENERIC_LABELS:
        return False
        
    # 2. Check if all words in the string are generic
    words = re.findall(r'\w+', name_lower)
    if not words:
        return False
        
    # Check if every word is in the generic set (splitting phrases like "content author computer")
    # We need a set of individual generic words for this check
    generic_words = set()
    for label in GENERIC_LABELS:
        generic_words.update(label.split())
        
    if all(word in generic_words for word in words):
        return False

    # 3. Check for version-like numbers
    if VERSION_PATTERN.search(name):
        return True

    # 4. Check for known tech keywords
    for tech in KNOWN_TECH:
        if tech in name_lower:
            return True

    # 5. Default behavior
    return False

def _fetch_kev_cve_ids() -> set[str]:
    """Helper to fetch the set of CVE IDs in the CISA KEV catalog."""
    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        # Extract only the CVE IDs from the KEV list for fast lookup
        return {item['cveID'] for item in response.json().get('vulnerabilities', [])}
    except Exception as e:
        print(f"Error fetching CISA KEV data: {e}")
        return set()

@lru_cache(maxsize=1)
def _fetch_kev_cve_ids_cached() -> set[str]:
    return _fetch_kev_cve_ids()

def search_vulnerabilities(tool_context: ToolContext, components: list[str]) -> ThreatSearchResults:
    """
    Searches NIST NVD and checks CISA KEV for recent and actively exploited 
    vulnerabilities relevant to the provided system components (e.g., ['Django 4.2', 'PostgreSQL 14']).
    
    The components list MUST contain specific software names and versions.
    Returns a structured list of high-priority threats that are relevant to the components.
    """
    
    from datetime import datetime, timezone, timedelta
    from dateutil import parser as date_parser

    found_threats = []
    kev_cve_ids = _fetch_kev_cve_ids_cached()

    # Normalize product identifiers: only search for explicit product names (not generic categories)
    product_identifiers = [c for c in components if _looks_like_software_identifier(c) and c.lower() not in GENERIC_LABELS]
    if not product_identifiers:
        print("No concrete product identifiers (OS/web server/DB/CI/CD tool) found; skipping NVD product CVE search.")
        return ThreatSearchResults(threats=[])

    # Prepare recency cutoff (5 years)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=365 * 5)

    # Query NVD for each product identifier, then post-filter by recency and product relevance
    for product in product_identifiers:
        try:
            # Use keyword search but rely on stricter post-filtering below
            results = nvdlib.searchCVE(
                keywordSearch=product,
                cvssV3Severity='HIGH',
                limit=200,
                key=NVD_API_KEY
            )

            for cve in results:
                try:
                    cve_id = cve.id

                    # Recency check: published or lastModified date must be within 5 years OR in KEV
                    pub_date = None
                    for attr in ("published", "publishedDate", "publishedDateTime", "published_date", "lastModified", "lastModifiedDate"):
                        if hasattr(cve, attr):
                            raw = getattr(cve, attr)
                            if raw:
                                try:
                                    pub_date = date_parser.parse(str(raw))
                                    break
                                except Exception:
                                    continue

                    if pub_date and pub_date.tzinfo is None:
                        pub_date = pub_date.replace(tzinfo=timezone.utc)

                    is_kev = cve_id in kev_cve_ids
                    if (pub_date and pub_date < cutoff) and not is_kev:
                        # Too old and not in KEV => skip
                        continue

                    # Extract summary
                    summary = cve.descriptions[0].value if cve.descriptions else "No summary available."
                    summary_lower = summary.lower()

                    # Product relevance: require that the CVE mentions the product explicitly in description or CPE/config
                    product_lower = product.lower()
                    relevant = False

                    # Check description text
                    if product_lower in summary_lower:
                        relevant = True

                    # Check CPEs / configurations if available (nvdlib objects often provide 'vulnerable' attributes)
                    if not relevant:
                        # Some nvdlib CVE objects expose 'vulnerable_configuration' or similar
                        for attr in ("cpe", "cpe23Uri", "vulnerable_configuration", "configurations", "vulnerable_configuration_cpe_list"):
                            if hasattr(cve, attr):
                                try:
                                    container = getattr(cve, attr)
                                    txt = str(container).lower()
                                    if product_lower in txt:
                                        relevant = True
                                        break
                                except Exception:
                                    continue

                    # If not relevant and not KEV, skip
                    if not relevant and not is_kev:
                        continue

                    # Get severity
                    severity = "N/A"
                    if cve.metrics:
                        if hasattr(cve.metrics, 'cvssMetricV31'):
                            severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity
                        elif hasattr(cve.metrics, 'cvssMetricV30'):
                            severity = cve.metrics.cvssMetricV30[0].cvssData.baseSeverity

                    # Build record
                    record = ThreatRecord(
                        cve_id=cve_id,
                        summary=summary,
                        severity=severity,
                        affected_products=product,
                        is_actively_exploited=is_kev,
                        source="NVD/CISA KEV"
                    )
                    found_threats.append(record)

                except Exception as e:
                    # Skip problematic CVE entries gracefully
                    print(f"Skipping CVE entry due to parsing error: {e}")

        except Exception as e:
            print(f"Error searching NVD for {product}: {e}")

    if not found_threats:
        print("No product-level CVEs were identified as directly applicable to this system. Only generic architectural threats will be reported.")

    return ThreatSearchResults(threats=found_threats)

def search_vulnerabilities_json(tool_context: ToolContext, components: list[str]) -> str:
    """
    Wrapper for search_vulnerabilities that returns a JSON string.
    Useful for agents or tools that expect string output.
    """
    result = search_vulnerabilities(tool_context, components)
    return result.model_dump_json()