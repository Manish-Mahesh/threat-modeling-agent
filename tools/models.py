from pydantic import BaseModel, Field
from typing import List, Optional

# --- Schema for Threat Research Agent Output ---
# This defines the structured data the Threat Research Agent must return to the Risk Assessment Agent.

class ThreatRecord(BaseModel):
    """A single structured vulnerability record."""
    cve_id: str = Field(description="The unique identifier for the vulnerability (e.g., CVE-2023-12345).")
    summary: str = Field(description="A brief, technical description of the vulnerability and its impact.")
    severity: str = Field(description="The CVSS qualitative severity rating (e.g., CRITICAL, HIGH, MEDIUM).")
    affected_products: str = Field(description="List of products/versions identified as affected.")
    is_actively_exploited: bool = Field(description="True if CISA has confirmed active exploitation (KEV Catalog).")
    source: str = Field(description="The data source (e.g., NVD, CISA KEV).")
    
    # Extended fields for mitigation generation
    cvss_vector: Optional[str] = Field(default=None, description="The CVSS vector string (e.g., CVSS:3.1/AV:N/AC:L...).")
    cvss_score: Optional[float] = Field(default=0.0, description="The numerical CVSS base score.")
    cwe_id: Optional[str] = Field(default=None, description="The Common Weakness Enumeration ID (e.g., CWE-89).")
    references: List[str] = Field(default_factory=list, description="List of vendor advisory URLs.")
    mitigation: Optional['MitigationStrategy'] = Field(default=None, description="Detailed mitigation strategy.")

class MitigationStrategy(BaseModel):
    """Structured mitigation guidance."""
    primary_fix: str = Field(description="The main action to take (e.g., Upgrade to version X).")
    configuration_changes: List[str] = Field(default_factory=list, description="Recommended configuration hardening.")
    access_control_changes: List[str] = Field(default_factory=list, description="IAM or network access control changes.")
    monitoring_actions: List[str] = Field(default_factory=list, description="What to log or monitor to detect exploitation.")
    additional_notes: List[str] = Field(default_factory=list, description="Other context or workarounds.")

class ThreatSearchResults(BaseModel):
    """Container for multiple threat records."""
    threats: List[ThreatRecord] = Field(description="A list of all found and filtered threat records.")


# --- Schema for Image Processor Tool Output (System Context) ---
# This defines the structured data the DiagramProcessorTool must extract from the image.

class ArchitectureSchema(BaseModel):
    """Schema for the structured architecture data extracted from a diagram."""
    components: List[str] = Field(description="List of all software/infra components and versions (e.g., 'Django 4.2', 'AWS RDS Postgres').")
    data_flow_narrative: str = Field(description="A concise narrative of how data moves between the main components.")
    trust_boundaries: List[str] = Field(description="List of security or network zones/boundaries identified.")


    # --- ADD THIS TO tools/models.py BELOW ThreatSearchResults ---

class RiskAssessmentReport(BaseModel):
    """The final structured output report for a single identified threat."""
    threat_name: str = Field(description="The short, descriptive name of the vulnerability or threat (e.g., 'Django RCE via CVE-2023-XXXX').")
    affected_component: str = Field(description="The component from the system architecture that is affected.")
    applicability_status: str = Field(description="Assessment of whether this threat is APPLICABLE, NOT APPLICABLE, or UNCERTAIN based on system context.")
    stride_category: str = Field(description="The primary STRIDE category of the threat (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, or Elevation of Privilege).")
    severity_score: str = Field(description="The qualitative risk score based on CVSS and KEV status (CRITICAL, HIGH, MEDIUM, LOW).")
    mitigation_suggestion: str = Field(description="A clear, immediate action item to mitigate this specific threat.")

class FinalReport(BaseModel):
    """Container for the complete list of assessed threats."""
    assessed_threats: List[RiskAssessmentReport] = Field(description="A complete list of structured risk assessment records.")