"""
ThreatRelevanceAgent
Filters and matches threats and CVEs to the actual system architecture using LLM-based reasoning.
"""
import os
from typing import List, Dict, Any
from google import genai
from google.genai import types
from tenacity import retry, stop_after_attempt, wait_exponential
from pydantic import BaseModel
from tools.models import ArchitecturalThreat, ThreatRecord, ArchitectureSchema

class CVERelevanceAssessment(BaseModel):
    cve_id: str
    relevance_status: str
    justification: str
    prerequisites: str = None
    exploitability: str = None
    likelihood: str = None

class ThreatRelevanceOutput(BaseModel):
    assessments: List[CVERelevanceAssessment]

THREAT_RELEVANCE_INSTRUCTION = """
You are a Vulnerability Intelligence Analyst.
Your job is to analyze a list of raw CVEs against a specific system architecture and determine their relevance.

RULES:
1. **Relevance Scoring:** For each CVE, determine if it is RELEVANT (High/Medium/Low) or IRRELEVANT.
   - **High:** Direct match, default config, remote exploit.
   - **Medium:** Requires specific module/config, or authentication.
   - **Low:** Unlikely version, complex prerequisites.
   - **Irrelevant:** Component not present, OS mismatch, or specific excluded configuration.

2. **Detailed Analysis:** For every relevant CVE, you MUST populate:
   - `relevance_status`: High/Medium/Low
   - `prerequisites`: e.g., "Requires authenticated user", "Requires ngx_http_mp4_module".
   - `exploitability`: e.g., "Remote Code Execution", "Local DoS".
   - `likelihood`: e.g., "High - Default config exposes this", "Low - Requires rare module".
   - `justification`: A short explanation of why this CVE matters to THIS architecture.

3. **Filtering:** discard any CVEs deemed "Irrelevant".

4. **Output:** Return a JSON object with a list of `assessments`.
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

class ThreatRelevanceAgent:
    """
    Matches generic threats and CVEs to the system, filtering out irrelevant ones using LLM.
    """
    def __init__(self, model_name: str = 'gemini-3-pro-preview'):
        self.agent = SimpleAgent(
            model_name=model_name,
            instruction=THREAT_RELEVANCE_INSTRUCTION,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=ThreatRelevanceOutput,
            )
        )

    def match_relevant_threats(self, inferred_components: List[Dict[str, Any]], generic_threats: Dict[str, Any], cve_threats: List[Any]) -> Dict[str, Any]:
        # generic_threats is now a dict with 'threats' and 'weaknesses' from ThreatKnowledgeAgent
        
        # Prepare simplified CVEs for analysis to save tokens and improve robustness
        simplified_cves = []
        cve_map = {} # Map ID to original object
        for c in cve_threats:
            cve_map[c.cve_id] = c
            simplified_cves.append({
                "cve_id": c.cve_id,
                "description": c.summary, # Changed from description to summary
                "affected_products": c.affected_products
            })
        
        prompt = f"""
        INFERRED COMPONENTS:
        {inferred_components}

        RAW CVES (Potential Matches):
        {simplified_cves}

        TASK: Filter and score these CVEs based on the component context.
        """

        relevant_cves = []
        try:
            response = self.agent.generate_content(prompt)
            import json
            data = json.loads(response.text)
            
            # Parse the output
            output = ThreatRelevanceOutput(**data)
            
            for assessment in output.assessments:
                if assessment.cve_id in cve_map:
                    original_cve = cve_map[assessment.cve_id]
                    # Update the original CVE with the assessment details
                    original_cve.relevance_status = assessment.relevance_status
                    original_cve.justification = assessment.justification
                    original_cve.prerequisites = assessment.prerequisites
                    original_cve.exploitability = assessment.exploitability
                    original_cve.likelihood = assessment.likelihood
                    
                    relevant_cves.append({
                        "cve": original_cve,
                        "score": 1.0, # Placeholder
                        "affected_components": [original_cve.affected_products]
                    })
                
        except Exception as e:
            print(f"Error filtering CVEs: {e}")
            # Fallback: return empty list on error
            relevant_cves = []

        # NEW: Promote Critical/High CVEs to Architectural Threats
        final_threats = generic_threats.get("threats", [])
        
        # Find the highest existing Threat ID to continue numbering
        max_id = 0
        for t in final_threats:
            try:
                # Assuming format T-XXX
                tid = int(t.threat_id.split('-')[1])
                if tid > max_id:
                    max_id = tid
            except:
                pass
        
        for item in relevant_cves:
            cve = item['cve']
            # Check if this is a high severity CVE that warrants a specific threat entry
            # We check for "High" or "Critical" severity, or explicit "High" relevance
            is_critical = False
            if cve.severity and cve.severity.upper() in ["HIGH", "CRITICAL"]:
                is_critical = True
            if cve.relevance_status and cve.relevance_status.upper() == "HIGH":
                is_critical = True
                
            if is_critical:
                max_id += 1
                new_threat_id = f"T-{max_id:03d}"
                
                # Create a new ArchitecturalThreat from the CVE
                new_threat = ArchitecturalThreat(
                    threat_id=new_threat_id,
                    category="Elevation of Privilege" if "RCE" in str(cve.exploitability) or "Code Execution" in cve.summary else "Denial of Service", # Simple heuristic
                    description=f"Exploitation of {cve.cve_id}: {cve.summary}",
                    affected_component=cve.affected_products,
                    severity="Critical" if cve.severity == "CRITICAL" else "High",
                    mitigation_steps=[f"Apply security updates to resolve {cve.cve_id}."],
                    preconditions=[cve.prerequisites or "Vulnerable version installed."],
                    impact=cve.exploitability or "System Compromise",
                    cwe_id=cve.cwe_id or "CWE-Unknown",
                    related_cve_id=cve.cve_id
                )
                final_threats.append(new_threat)
                print(f"   -> Promoted {cve.cve_id} to Architectural Threat {new_threat_id}")

        return {
            "relevant_threats": final_threats,
            "relevant_weaknesses": generic_threats.get("weaknesses", []),
            "relevant_cves": relevant_cves
        }
