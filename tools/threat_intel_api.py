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

# Strict Product Mapping for CPE Matching
# Maps inferred component names (lowercase) to NVD search terms and allowed CPE vendor/product pairs.
PRODUCT_MAPPING = {
    "nginx web server": {
        "search_term": "nginx",
        "allowed_vendors": {"nginx", "f5"}, # F5 owns Nginx
        "allowed_products": {"nginx"}
    },
    "nginx": {
        "search_term": "nginx",
        "allowed_vendors": {"nginx", "f5"},
        "allowed_products": {"nginx"}
    },
    "redis cache": {
        "search_term": "redis",
        "allowed_vendors": {"redis", "redislabs", "pivotal_software"}, # Pivotal also distributed Redis
        "allowed_products": {"redis"}
    },
    "redis": {
        "search_term": "redis",
        "allowed_vendors": {"redis", "redislabs", "pivotal_software"},
        "allowed_products": {"redis"}
    },
    "mysql": {
        "search_term": "mysql",
        "allowed_vendors": {"oracle", "mysql"},
        "allowed_products": {"mysql", "mysql_server"}
    },
    "postgresql": {
        "search_term": "postgresql",
        "allowed_vendors": {"postgresql", "postgresql_global_development_group"},
        "allowed_products": {"postgresql"}
    },
    "wordpress site": {
        "search_term": "wordpress",
        "allowed_vendors": {"wordpress"},
        "allowed_products": {"wordpress"}
    }
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

def _parse_cpe(cpe_str: str) -> dict:
    """Parses a CPE 2.3 string into a dict of parts."""
    # CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    parts = cpe_str.split(':')
    if len(parts) < 5:
        return {}
    return {
        "vendor": parts[3],
        "product": parts[4]
    }

def search_vulnerabilities(tool_context: ToolContext, components: list[str]) -> ThreatSearchResults:
    """
    Searches NIST NVD and checks CISA KEV for recent and actively exploited 
    vulnerabilities relevant to the provided system components.
    
    Uses strict CPE matching and severity filtering.
    """
    
    from datetime import datetime, timezone, timedelta
    from dateutil import parser as date_parser

    found_threats = []
    kev_cve_ids = _fetch_kev_cve_ids_cached()

    # Normalize product identifiers
    product_identifiers = [c for c in components if _looks_like_software_identifier(c) and c.lower() not in GENERIC_LABELS]
    if not product_identifiers:
        print("No concrete product identifiers (OS/web server/DB/CI/CD tool) found; skipping NVD product CVE search.")
        return ThreatSearchResults(threats=[])

    # Prepare recency cutoff (5 years)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=365 * 5)

    for product in product_identifiers:
        product_lower = product.lower()
        
        # Determine search parameters based on mapping
        search_term = product
        allowed_vendors = set()
        allowed_products = set()
        
        if product_lower in PRODUCT_MAPPING:
            mapping = PRODUCT_MAPPING[product_lower]
            search_term = mapping["search_term"]
            allowed_vendors = mapping["allowed_vendors"]
            allowed_products = mapping["allowed_products"]
        else:
            # Fallback for unmapped products: use the product name itself as a loose filter
            # But we still want to be somewhat strict if possible. 
            # For now, we'll just use the product name as the search term.
            pass

        try:
            # Query NVD
            results = nvdlib.searchCVE(
                keywordSearch=search_term,
                cvssV3Severity='HIGH', # Initial filter, we'll refine later
                limit=100, # Reduced limit for stricter search
                key=NVD_API_KEY
            )
            # print(f"DEBUG: Found {len(results)} results for {search_term}")

            for cve in results:
                try:
                    cve_id = cve.id
                    is_kev = cve_id in kev_cve_ids

                    # 1. Severity Filter & Data Extraction
                    severity = "UNKNOWN"
                    score = 0.0
                    vector = None
                    
                    if cve.metrics:
                        if hasattr(cve.metrics, 'cvssMetricV31'):
                            metric = cve.metrics.cvssMetricV31[0].cvssData
                            severity = metric.baseSeverity
                            score = metric.baseScore
                            vector = metric.vectorString
                        elif hasattr(cve.metrics, 'cvssMetricV30'):
                            metric = cve.metrics.cvssMetricV30[0].cvssData
                            severity = metric.baseSeverity
                            score = metric.baseScore
                            vector = metric.vectorString
                        elif hasattr(cve.metrics, 'cvssMetricV2'):
                            # Fallback for older CVEs
                            metric = cve.metrics.cvssMetricV2[0].cvssData
                            score = metric.baseScore
                            severity = "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"
                            vector = metric.vectorString

                    if severity not in ["HIGH", "CRITICAL"] and not is_kev:
                        continue

                    # Extract CWE
                    cwe_id = None
                    if hasattr(cve, 'cwe'):
                        # nvdlib might return a list or object
                        if isinstance(cve.cwe, list) and len(cve.cwe) > 0:
                            cwe_id = cve.cwe[0].value

                    # Extract References
                    references = []
                    if hasattr(cve, 'references'):
                        for ref in cve.references:
                            if hasattr(ref, 'url'):
                                references.append(ref.url)

                    # 2. Recency Filter
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

                    if (pub_date and pub_date < cutoff) and not is_kev:
                        continue

                    # 3. Strict Product/CPE Matching
                    relevant = False
                    
                    # If we have a strict mapping, enforce it
                    if allowed_vendors and allowed_products:
                        # Check CPEs
                        cpes = []
                        if hasattr(cve, 'cpe'):
                            cpes.extend(cve.cpe)
                        
                        # Also check configurations for cpeMatch
                        if hasattr(cve, 'configurations'):
                            # This is a list of objects
                            for config in cve.configurations:
                                if hasattr(config, 'nodes'):
                                    for node in config.nodes:
                                        if hasattr(node, 'cpeMatch'):
                                            for match in node.cpeMatch:
                                                if hasattr(match, 'criteria'):
                                                    cpes.append(match.criteria)

                        for cpe_str in cpes:
                            # Ensure cpe_str is a string
                            if not isinstance(cpe_str, str):
                                if hasattr(cpe_str, 'criteria'):
                                    cpe_str = cpe_str.criteria
                                else:
                                    cpe_str = str(cpe_str)

                            parsed = _parse_cpe(cpe_str)
                            if parsed.get("vendor") in allowed_vendors and parsed.get("product") in allowed_products:
                                relevant = True
                                break
                    else:
                        # Fallback: Description match (Legacy behavior but stricter)
                        # Only if no mapping exists
                        summary = cve.descriptions[0].value if cve.descriptions else ""
                        if product_lower in summary.lower():
                            relevant = True

                    if not relevant:
                        continue

                    # Build record
                    summary = cve.descriptions[0].value if cve.descriptions else "No summary available."
                    record = ThreatRecord(
                        cve_id=cve_id,
                        summary=summary,
                        severity=severity,
                        affected_products=product, # Tie to the component name
                        is_actively_exploited=is_kev,
                        source="NVD/CISA KEV",
                        cvss_vector=vector,
                        cvss_score=score,
                        cwe_id=cwe_id,
                        references=references
                    )
                    found_threats.append(record)

                except Exception as e:
                    # Skip problematic CVE entries gracefully
                    continue

        except Exception as e:
            print(f"Error searching NVD for {product}: {e}")

    if not found_threats:
        print("No product-level CVEs were identified as directly applicable to this system.")

    return ThreatSearchResults(threats=found_threats)

def search_vulnerabilities_json(tool_context: ToolContext, components: list[str]) -> str:
    """
    Wrapper for search_vulnerabilities that returns a JSON string.
    Useful for agents or tools that expect string output.
    """
    result = search_vulnerabilities(tool_context, components)
    return result.model_dump_json()
