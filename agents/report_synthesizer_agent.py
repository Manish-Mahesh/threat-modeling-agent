"""
ReportSynthesizerAgent
Combines relevant threats, CVEs, and attack paths into a final executive report following a strict 14-section format.
"""
import os
import json
from typing import Dict, Any, List
from datetime import datetime
from google import genai
from google.genai import types
from tenacity import retry, stop_after_attempt, wait_exponential
from tools.models import ArchitectureSchema, ArchitecturalThreat, CVE, MitigationStrategy, AttackPath, ArchitecturalWeakness

REPORT_SYNTHESIZER_INSTRUCTION = """
You are a senior security architect AI specializing in automated threat modeling. 
You will be given an architecture diagram, a JSON description, or mixed inputs. 
Your job is to generate a complete and accurate threat model based ONLY on what is visible or explicitly stated. 
Do not invent components or technologies.

============================================================
1. ARCHITECTURE EXTRACTION
============================================================
Extract the following from the input:

1.1 Components  
Return as a clean list.

1.2 Data Flows  
List each directional flow as: Source → Destination, including protocol or data type if visible.

1.3 Trust Boundaries  
Identify: Internet boundary, workstation zone, CI/CD zone, dev/staging/prod zones, network boundaries.  
If anything is missing, clearly state assumptions:  
“Assumption: X appears inside Y boundary because Z.”

Never hallucinate components.

============================================================
2. COMPONENT INVENTORY TABLE
============================================================
Create:

| Component | Type | Criticality (Low/Med/High/Critical) | Notes |

Criticality must be based on:
- Business impact  
- Data sensitivity  
- Connectivity to external networks  
- Privilege level  

============================================================
3. STRIDE THREAT ENUMERATION
============================================================
For each component AND each data flow, generate ONLY relevant STRIDE threats.

Create a table with the following columns:
| ID | STRIDE | CWE | Component | Description | Severity | Mitigations |

Each threat must include:

- ID: T-XXX  
- STRIDE category  
- CWE ID (e.g., CWE-79). **CRITICAL:** You MUST populate this column. Use the `cwe_id` field from the input data. If missing, INFER the most accurate CWE based on the description.
- Component Name
- Description (very specific to THIS architecture)  
- Preconditions  
- Impact  
- Severity (Low/Med/High/Critical)  
- Mitigations (2–4 realistic items)

Do NOT generate generic threats unless they logically apply.

============================================================
4. ARCHITECTURAL WEAKNESSES
============================================================
Identify 5–10 systemic weaknesses such as:
- Shared credentials  
- Poor boundary separation  
- Insecure deployment pathways  
- Missing audit logs  
- Overprivileged automation  

Each must include description + impact.

============================================================
5. CVE DISCOVERY (REAL AND RELEVANT ONLY)
============================================================
Rules:

1. Only produce CVEs if the architecture diagram clearly implies a specific product  
   (e.g., Redis, Nginx, Windows, Jenkins, MySQL).  
2. If version is unknown:  
   Choose CVEs affecting broad ranges or all versions.  
3. If product cannot be reliably inferred:  
   Output: “CVE analysis skipped due to insufficient product detail.”

For each CVE include:
- ID  
- Component  
- CVSS score  
- Summary  
- Preconditions  
- Relevance (High/Med/Low)  
- Why it applies  

NEVER invent CVEs.

============================================================
6. THREAT ↔ CVE MATRIX
============================================================

| Threat ID | CVE | Relationship (Amplifies, Enables, Related Weakness) |

Only populate if CVEs exist.
Ensure that if a Threat ID is derived from a CVE (e.g., has a related_cve_id), it is listed here with a "Direct" relationship.

============================================================
7. ATTACK PATH SIMULATIONS
============================================================
Generate 2–3 realistic attack paths referencing Threat IDs and CVEs.

Each path must include:
- Name  
- Impact  
- Likelihood  
- Step-by-step chain (4–6 steps)

Paths must strictly follow the architecture.

============================================================
8. COMPONENT SECURITY PROFILES
============================================================
For each component:

- Role summary  
- Overall risk rating  
- Top 3 threats affecting this component  
- 3–5 prioritized mitigations  

============================================================
9. NIST 800-53 REV5 CONTROL MAPPING
============================================================
For all High/Critical threats:

- Map 2–4 relevant controls  
- Explain how each control mitigates the risk  

Controls must be meaningful and non-repetitive.

============================================================
10. HARDENING PLAN
============================================================

10.1 Quick Wins (under 1 day)  
- Patches  
- Network ACL tightening  
- Log enablement  
- Secret rotation

10.2 Short-Term (1–4 weeks)  
- CI/CD isolation  
- Artifact signing  
- Least privilege role reviews  
- WAF rules

10.3 Long-Term (1–3 months)  
- Zero trust  
- Full secrets manager  
- Telemetry and audit infrastructure  
- Immutable builds

============================================================
11. CONSISTENCY RULES
============================================================
- Executive summary must match all counts.  
- No contradictions between tables, threats, CVEs, and matrices.  
- No invented technologies or products.  
- Threat IDs must be unique and referenced consistently.  
- If 0 CVEs exist, do NOT include CVE mitigation steps.

============================================================
12. OUTPUT FORMAT
============================================================
- Use clean, readable markdown.  
- Use headers for each major section.  
- Appendices allowed for long CVE lists.  
- Avoid clutter and redundancy.
"""

class SimpleAgent:
    def __init__(self, model_name, instruction, config=None):
        self.client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
        self.model_name = model_name
        self.instruction = instruction
        self.config = config

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=4, max=10))
    def generate_content(self, prompt):
        config = self.config
        if config is None:
            config = types.GenerateContentConfig()
        
        if not config.system_instruction:
            config.system_instruction = self.instruction
            
        return self.client.models.generate_content(
            model=self.model_name,
            contents=prompt,
            config=config
        )

class ReportSynthesizerAgent:
    """
    Synthesizes the final threat model report from relevant threats, CVEs, and attack paths.
    """
    def __init__(self, model_name: str = 'gemini-3-pro-preview'):
        self.agent = SimpleAgent(
            model_name=model_name,
            instruction=REPORT_SYNTHESIZER_INSTRUCTION
        )

    def synthesize_report(self, match_results: Dict[str, Any], architecture: ArchitectureSchema, attack_paths: List[AttackPath]) -> Dict[str, Any]:
        # This method prepares the data structure. 
        # We return the raw objects to maintain compatibility with main.py (which expects objects for the summary),
        # but we will serialize them to JSON inside generate_markdown_report for the LLM.
        
        relevant_threats: List[ArchitecturalThreat] = match_results.get("relevant_threats", [])
        relevant_weaknesses: List[ArchitecturalWeakness] = match_results.get("relevant_weaknesses", [])
        relevant_cves: List[Dict[str, Any]] = match_results.get("relevant_cves", [])
        
        return {
            "architecture": architecture,
            "threats": relevant_threats,
            "weaknesses": relevant_weaknesses,
            "cves": relevant_cves, # This is a list of dicts like {'cve': ThreatRecord object, ...}
            "attack_paths": attack_paths,
            "project_name": architecture.project_name,
            "executive_summary": f"Threat Model for {architecture.project_name} generated on {datetime.now().strftime('%Y-%m-%d')}"
        }

    def generate_markdown_report(self, report_data: Dict[str, Any]) -> str:
        """
        Generates a Markdown formatted string from the report data using the LLM.
        """
        
        # Helper to serialize Pydantic models and other types
        def json_serial(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if hasattr(obj, "model_dump"):
                return obj.model_dump()
            raise TypeError (f"Type {type(obj)} not serializable")

        # Convert the report data to a JSON string for the prompt
        try:
            data_str = json.dumps(report_data, indent=2, default=json_serial)
        except Exception as e:
            return f"Error serializing report data: {e}"

        prompt = f"""
        INPUT DATA (Structured Threat Model):
        {data_str}

        TASK:
        Using the provided input data, generate the final Threat Model Report following the structure defined in your system instruction.
        Ensure you incorporate all the identified threats, CVEs, and attack paths from the input data.
        Refine the descriptions and mitigations to be professional and actionable.
        """

        try:
            response = self.agent.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error generating report with LLM: {e}\n\nFallback to raw data:\n{data_str}"
