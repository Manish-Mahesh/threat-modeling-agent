# agents/planner_agent.py

import os
from google import genai
from google.genai import types
from google.adk.tools import FunctionTool
from tenacity import retry, stop_after_attempt, wait_exponential



PLANNER_SYSTEM_INSTRUCTION = """
You are the Root Threat Modeling Orchestration Agent, a meticulous cybersecurity expert.
Your primary job is to manage the entire threat modeling workflow, ensuring all tasks are delegated and executed in sequence.

Your steps MUST be:
1. **Analyze Input:** Receive the user's request and the file path to the system architecture diagram.
2. **Architecture Extraction (Tool Use):** Call the 'process_architecture_diagram' tool with the image path to extract structured components.
3. **Threat Identification (Delegation):** Use the list of components returned from the previous step to call the 'search_vulnerabilities' tool.
4. **Risk Assessment (Delegation):** Pass the results from the threat search and the initial architecture data to the Risk Assessment Agent.
5. **Synthesis:** Take the final structured risk assessment report and synthesize it into a clear, professional, human-readable threat model report for the user.

You are NOT allowed to perform any web search, direct risk calculation, or detailed analysis yourself. You must strictly delegate these tasks using your defined tools.
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

# 2. Define the Agent Factory Function (Accepting tools as argument)
def create_planner_agent(tools: list, model_name: str = 'gemini-2.0-flash'):
    """Creates and configures the Root Planner Agent."""
    
    planner_agent = SimpleAgent(
        model_name=model_name,
        instruction=PLANNER_SYSTEM_INSTRUCTION,
        tools=[FunctionTool(t) for t in tools], # Convert functions to ADK Tool objects
    )
    
    return planner_agent