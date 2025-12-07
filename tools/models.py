from pydantic import BaseModel, Field
from typing import List, Optional

# --- Schema for Threat Research Agent Output ---
# This defines the structured data the Threat Research Agent must return to the Risk Assessment Agent.

class MitigationStrategy(BaseModel):
    """Structured mitigation guidance."""
    primary_fix: str = Field(description="The main action to take (e.g., Upgrade to version X).")
    configuration_changes: List[str] = Field(default_factory=list, description="Recommended configuration hardening.")
    access_control_changes: List[str] = Field(default_factory=list, description="IAM or network access control changes.")
    monitoring_actions: List[str] = Field(default_factory=list, description="What to log or monitor to detect exploitation.")
    nist_controls: List[str] = Field(default_factory=list, description="Relevant NIST 800-53 controls (e.g., 'SI-2', 'AC-3').")
    additional_notes: List[str] = Field(default_factory=list, description="Other context or workarounds.")

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
    mitigation: Optional[MitigationStrategy] = Field(default=None, description="Detailed mitigation strategy.")

    # New fields for detailed analysis
    relevance_status: Optional[str] = Field(default="Unknown", description="High/Medium/Low/Irrelevant based on architecture.")
    prerequisites: Optional[str] = Field(default=None, description="Auth required, module needed, etc.")
    exploitability: Optional[str] = Field(default=None, description="Remote, local, privileged, etc.")
    likelihood: Optional[str] = Field(default=None, description="Likelihood given the architecture.")
    justification: Optional[str] = Field(default=None, description="Reasoning for the relevance score.")

# Alias for backward compatibility with agents expecting 'CVE'
CVE = ThreatRecord

class ArchitecturalWeakness(BaseModel):
    """A missing control or architectural flaw."""
    weakness_id: str = Field(description="Unique ID (e.g., W-001).")
    title: str = Field(description="Title of the weakness.")
    description: str = Field(description="Detailed description of the missing control or weakness.")
    impact: str = Field(description="Potential impact.")
    mitigation: str = Field(description="Recommended mitigation.")

class ArchitecturalThreat(BaseModel):
    """A generic STRIDE-based threat derived from architecture analysis."""
    threat_id: str = Field(description="Unique ID (e.g., T-001).")
    category: str = Field(description="STRIDE category (e.g., Spoofing).")
    description: str = Field(description="Description of the threat scenario.")
    affected_component: str = Field(description="The component at risk.")
    affected_asset: Optional[str] = Field(default=None, description="The asset (data/service) at risk.")
    trust_boundary: Optional[str] = Field(default=None, description="The trust boundary crossed (if any).")
    severity: str = Field(description="Qualitative severity (High, Medium, Low).")
    mitigation_steps: List[str] = Field(default_factory=list, description="High-level mitigation steps.")
    preconditions: List[str] = Field(default_factory=list, description="Conditions required for the threat to be realized.")
    impact: Optional[str] = Field(default=None, description="Potential impact of the threat.")
    example: Optional[str] = Field(default=None, description="Real-world example of this threat.")
    cwe_id: Optional[str] = Field(default=None, description="Related CWE ID (e.g., CWE-79).")
    related_cve_id: Optional[str] = Field(default=None, description="Related CVE ID if this threat is derived from a specific vulnerability (e.g., CVE-2025-21187).")

class ThreatSearchResults(BaseModel):
    """Container for multiple threat records."""
    threats: List[ThreatRecord] = Field(description="A list of all found and filtered threat records.")


# --- Schema for Image Processor Tool Output (System Context) ---
# This defines the structured data the DiagramProcessorTool must extract from the image.

class Component(BaseModel):
    name: str = Field(description="Name of the component (e.g., 'Primary Database').")
    type: str = Field(description="Type of the component (e.g., 'Database', 'Web Server', 'Load Balancer').")

class DataFlow(BaseModel):
    source: str = Field(description="Source component name.")
    destination: str = Field(description="Destination component name.")
    protocol: str = Field(description="Communication protocol (e.g., 'HTTPS', 'SQL', 'TCP').")

class ArchitectureSchema(BaseModel):
    """Schema for the structured architecture data extracted from a diagram."""
    project_name: str = Field(default="Untitled Project", description="Name of the system or project.")
    description: str = Field(default="No description provided.", description="High-level description of the system.")
    components: List[Component] = Field(description="List of all software/infra components.")
    data_flows: List[DataFlow] = Field(description="List of data flows between components.")
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

class AttackStep(BaseModel):
    step_id: int = Field(description="Step number in the attack path.")
    description: str = Field(description="Description of the attack step.")
    technique: str = Field(description="The technique used (e.g., 'Exploit CVE-2021-32625', 'Brute Force').")
    target_component: str = Field(description="The component targeted in this step.")

class AttackPath(BaseModel):
    path_id: str = Field(description="Unique ID for the attack path (e.g., AP-01).")
    title: str = Field(description="Short title of the attack path.")
    steps: List[AttackStep] = Field(description="Ordered list of steps in the attack path.")
    impact: str = Field(description="Potential impact if this path is successfully executed.")
    likelihood: str = Field(description="Likelihood of this path being exploited (High, Medium, Low).")

class FinalReport(BaseModel):
    """Container for the complete list of assessed threats."""
    assessed_threats: List[RiskAssessmentReport] = Field(description="A complete list of structured risk assessment records.")
    attack_paths: List[AttackPath] = Field(default_factory=list, description="Simulated attack paths.")