import os
from typing import List, Dict, Any
from google import genai
from google.genai import types
from tenacity import retry, stop_after_attempt, wait_exponential
from tools.models import ArchitectureSchema, AttackPath, ArchitecturalThreat, CVE
from pydantic import BaseModel, Field

class AttackPathList(BaseModel):
    paths: List[AttackPath]

ATTACK_PATH_SYSTEM_INSTRUCTION = """
You are an expert Red Teamer and Attack Path Simulator.
Your job is to analyze a system architecture and a list of identified threats (STRIDE and CVEs) to construct realistic, multi-step attack paths.

You must:
1.  **Analyze Connectivity:** Look at the data flows and trust boundaries. Can an attacker move from the Internet to the Web Server? From Web Server to Database?
2.  **Chain Vulnerabilities:** Use the provided threats. For example, if there is an RCE on the Web Server (CVE-XXXX) and a weak ACL on the Database, chain them.
3.  **Simulate Pivots:** Describe how an attacker pivots from one component to another.
4.  **Realistic Scenarios:** Focus on high-impact scenarios like Data Exfiltration, Ransomware, or Full System Compromise.
5.  **Mandatory Output:** You MUST generate at least 2 distinct attack paths.

Output Format:
Return a JSON object containing a list of 'AttackPath' objects wrapped in a 'paths' key.
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

class AttackPathAgent:
    def __init__(self, model_name: str = 'gemini-3-pro-preview'):
        self.agent = SimpleAgent(
            model_name=model_name,
            instruction=ATTACK_PATH_SYSTEM_INSTRUCTION,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=AttackPathList,
            )
        )

    def generate_attack_paths(self, architecture: ArchitectureSchema, threats: List[ArchitecturalThreat], cves: List[Dict[str, Any]]) -> List[AttackPath]:
        # Prepare the input for the LLM
        threat_descriptions = []
        for t in threats:
            threat_descriptions.append(f"Threat {t.threat_id}: {t.category} on {t.affected_component} - {t.description}")
        
        cve_descriptions = []
        for item in cves:
            cve: CVE = item["cve"]
            cve_descriptions.append(f"CVE {cve.cve_id}: {cve.severity} on {', '.join(item.get('affected_components', []))} - {cve.summary}")

        prompt = f"""
        SYSTEM ARCHITECTURE:
        {architecture.model_dump_json(indent=2)}

        IDENTIFIED THREATS:
        {chr(10).join(threat_descriptions)}

        IDENTIFIED VULNERABILITIES (CVEs):
        {chr(10).join(cve_descriptions)}

        TASK: Generate at least 2 realistic attack paths based on the above information.
        """

        try:
            response = self.agent.generate_content(prompt)
            import json
            data = json.loads(response.text)
            # Handle both direct list (if model ignores schema wrapper) or wrapped object
            if isinstance(data, list):
                 return [AttackPath(**p) for p in data]
            return [AttackPath(**p) for p in data.get("paths", [])]
        except Exception as e:
            print(f"Error generating attack paths: {e}")
            return []
