import os
from google import genai
from google.genai import types
from tenacity import retry, stop_after_attempt, wait_exponential

# Import the Pydantic schemas
from tools.models import ThreatSearchResults, ArchitectureSchema, FinalReport 

# 1. Define the Risk Assessment Agent's Persona and Responsibilities
ASSESSMENT_SYSTEM_INSTRUCTION = """
You are the Risk Assessment and Mitigation Agent. Your sole responsibility is to evaluate raw threat data 
against a given system architecture context and produce a structured, actionable risk report.

You MUST follow these rules:
1. **Contextualize (Day 3: Memory):** Use the provided system architecture and trust boundaries (ArchitectureSchema) to determine if a threat is APPLICABLE to the system. If the threat affects 'MongoDB' and the architecture uses 'PostgreSQL', the status is NOT APPLICABLE.
2. **Categorize (Day 4: Evaluation):** For every APPLICABLE threat, assign a primary STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, or Elevation of Privilege).
3. **Mitigate:** Provide a clear, immediate mitigation suggestion for every APPLICABLE threat.
4. **Structured Output:** Your final output MUST be a single JSON object that strictly conforms to the 'FinalReport' schema, containing a list of structured 'RiskAssessmentReport' objects. 
"""

class SimpleAgent:
    def __init__(self, model_name, instruction, tools=None, config=None):
        self.client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
        self.model_name = model_name
        self.instruction = instruction
        self.tools = tools or []
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

# 2. Define the Agent Factory Function
def create_assessment_agent(model_name: str = 'gemini-2.0-flash'):
    """
    Creates and configures the Risk Assessment Agent. This agent is primarily a reasoning agent 
    and typically does not need external tools, relying instead on its prompt and input data.
    """
    
    # This agent performs reasoning on the data it receives, so it typically has no tools.
    assessment_agent = SimpleAgent(
        model_name=model_name,
        instruction=ASSESSMENT_SYSTEM_INSTRUCTION,
        # Force the model to output the final structured report
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=FinalReport,
        ),
        tools=[], # No external tools needed, just pure reasoning
    )
    
    return assessment_agent


# 3. Define the Run Function (The execution logic for the Planner Agent to call)
def run_assessment(
    agent, 
    architecture_data: ArchitectureSchema, 
    raw_threats: ThreatSearchResults
) -> dict:
    """Runs the assessment agent on the gathered data."""
    
    # Combine the architecture context and the raw threats into a single prompt input
    prompt_input = f"""
    SYSTEM ARCHITECTURE (CONTEXT):
    {architecture_data.model_dump_json(indent=2)}
    
    RAW THREATS (RESEARCH):
    {raw_threats.model_dump_json(indent=2)}
    
    TASK: Based on the system architecture and the raw threats, produce the final structured risk assessment report.
    """
    
    # The LLMAgent call uses the structured output config defined in its creation
    response = agent.generate_content(prompt_input)
    
    # response.text is the JSON string of the FinalReport object
    return response.text