"""
ThreatKnowledgeAgent
Generates detailed architectural threats and weaknesses using LLM-based STRIDE analysis.
"""
import os
from typing import List, Dict, Any
from google import genai
from google.genai import types
from tenacity import retry, stop_after_attempt, wait_exponential
from pydantic import BaseModel, Field
from tools.models import ArchitecturalThreat, ArchitecturalWeakness, ArchitectureSchema

class ThreatKnowledgeOutput(BaseModel):
    threats: List[ArchitecturalThreat]
    weaknesses: List[ArchitecturalWeakness]

class CWEValidationItem(BaseModel):
    threat_id: str
    is_accurate: bool
    corrected_cwe_id: str = Field(description="The correct CWE ID if inaccurate, else the original.")
    reason: str

class CWEValidationOutput(BaseModel):
    corrections: List[CWEValidationItem]

THREAT_KNOWLEDGE_INSTRUCTION = """
You are a STRIDE Threat Modeling Expert.
Your job is to analyze a system architecture and generate a comprehensive list of threats and architectural weaknesses.

RULES:
1. **Deep STRIDE Analysis:** For EACH component, generate at least 6-10 detailed threats.
   - **S**poofing
   - **T**ampering
   - **R**epudiation
   - **I**nformation Disclosure
   - **D**enial of Service
   - **E**levation of Privilege
   - **Avoid generic filler.** Use specific technology knowledge (e.g., "Redis RESP protocol injection", "Nginx worker process buffer overflow").
   - **CWE Mapping:** For each threat, identify the most relevant CWE ID (e.g., CWE-79, CWE-89). **REQUIRED.**

2. **Data Flow Threats:** For every data flow, identify:
   - Tampering (integrity)
   - Information Disclosure (confidentiality)
   - Denial of Service (availability)
   - Protocol-specific risks (e.g., HTTP/2 downgrade, unencrypted TCP).

3. **Architectural Weaknesses:** Identify missing security controls (e.g., "Lack of WAF", "Missing Network Segmentation", "No Audit Logging").

4. **Output Format:** Return a JSON object with two lists: 'threats' and 'weaknesses'.
"""

CWE_VALIDATION_INSTRUCTION = """
You are a CWE (Common Weakness Enumeration) Expert.
Your task is to validate the mapping between a Threat Description and its assigned CWE ID.

RULES:
1. Review the provided Threat Description and the assigned CWE ID.
2. Determine if the assigned CWE ID is the most accurate and specific match.
3. If it is accurate, set `is_accurate` to true.
4. If it is inaccurate or generic (e.g., using a category instead of a weakness), provide the CORRECT `corrected_cwe_id` and a brief `reason`.
5. Be strict. We want precise CWE mappings.
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

class ThreatKnowledgeAgent:
    """
    Produces detailed architectural threats and weaknesses based on inferred component types and STRIDE analysis.
    """
    def __init__(self, model_name: str = 'gemini-3-pro-preview'):
        self.agent = SimpleAgent(
            model_name=model_name,
            instruction=THREAT_KNOWLEDGE_INSTRUCTION,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=ThreatKnowledgeOutput,
            )
        )
        # Validator Agent
        self.validator_agent = SimpleAgent(
            model_name=model_name,
            instruction=CWE_VALIDATION_INSTRUCTION,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=CWEValidationOutput,
            )
        )

    def _validate_cwe_mappings(self, threats: List[ArchitecturalThreat]) -> List[ArchitecturalThreat]:
        if not threats:
            return []
            
        # Prepare simplified list for validation to save tokens
        threat_summaries = []
        for t in threats:
            threat_summaries.append({
                "threat_id": t.threat_id,
                "description": t.description,
                "assigned_cwe": t.cwe_id
            })
            
        prompt = f"""
        VALIDATE THESE MAPPINGS:
        {threat_summaries}
        """
        
        try:
            response = self.validator_agent.generate_content(prompt)
            import json
            data = json.loads(response.text)
            validation_output = CWEValidationOutput(**data)
            
            # Create a map of corrections
            corrections_map = {item.threat_id: item for item in validation_output.corrections}
            
            # Apply corrections
            for threat in threats:
                if threat.threat_id in corrections_map:
                    correction = corrections_map[threat.threat_id]
                    if not correction.is_accurate and correction.corrected_cwe_id:
                        print(f"   -> Correcting CWE for {threat.threat_id}: {threat.cwe_id} -> {correction.corrected_cwe_id} ({correction.reason})")
                        threat.cwe_id = correction.corrected_cwe_id
                        
        except Exception as e:
            print(f"⚠️ CWE Validation failed: {e}")
            
        return threats

    def generate_threats(self, inferred_components: List[Dict[str, Any]], architecture: ArchitectureSchema) -> Dict[str, Any]:
        prompt = f"""
        SYSTEM ARCHITECTURE:
        {architecture.model_dump_json(indent=2)}

        INFERRED COMPONENTS:
        {inferred_components}

        TASK: Generate detailed STRIDE threats and architectural weaknesses for this system.
        """

        try:
            response = self.agent.generate_content(prompt)
            import json
            data = json.loads(response.text)
            # Convert to Pydantic model to ensure objects are returned, not dicts
            output = ThreatKnowledgeOutput(**data)
            
            # Validate CWEs
            print("   ... Validating CWE mappings...")
            validated_threats = self._validate_cwe_mappings(output.threats)

            return {
                "threats": validated_threats,
                "weaknesses": output.weaknesses
            }
        except Exception as e:
            print(f"Error generating threats: {e}")
            return {"threats": [], "weaknesses": []}
