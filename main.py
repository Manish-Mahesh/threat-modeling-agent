import os
import json
import argparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# main.py (NEW, CORRECT)
from google.adk.tools import tool_context

# Import Agent Factory Functions
from agents.planner_agent import create_planner_agent
from agents.assessment_agent import create_assessment_agent, run_assessment

# Import Custom Tool Functions (used to be imported by the agent files)
from tools.diagram_processor import process_architecture_diagram
from tools.threat_intel_api import search_vulnerabilities

# Import Data Models for Validation
from tools.models import ArchitectureSchema, ThreatSearchResults, FinalReport


def main(image_path: str):
    """
    Initializes and orchestrates the Threat Modeling Multi-Agent System.
    """
    
    print("🤖 Initializing Threat Modeling Agents...")
    
    # --- 1. Initialize Agents with Tool Isolation (CIRCULAR DEPENDENCY FIX) ---
    
    # Define the tools the Planner Agent needs access to
    planner_tool_functions = [
        process_architecture_diagram,
        search_vulnerabilities,
    ]
    
    # Pass the tool functions list to the creation method
    planner_agent = create_planner_agent(
        tools=planner_tool_functions,
        model_name='gemini-2.5-flash'
    )
    assessment_agent = create_assessment_agent(model_name='gemini-2.5-flash')
    
    print("-" * 50)
    print(f"\n▶️ Starting Threat Modeling Workflow for image: {image_path}")
    
    # --- 2. Workflow Execution ---
    
    # 2A. Architecture Extraction (Calls the DiagramProcessorTool)
    print("\n✅ STEP 1: Calling Diagram Processor Tool (Vision)...")
    
    # We retrieve the tool function from the Planner Agent's tool list for execution
    # This is a simulation of the planner's first action.
    diagram_tool_func = planner_agent.tools[0].func
    architecture_data_json = diagram_tool_func(None, image_path)
    
    try:
        # Validate and convert the JSON output to the Pydantic model
        architecture_data = ArchitectureSchema.model_validate_json(architecture_data_json)
        print("   -> Architecture data extracted and validated.")
        print(f"   -> Components identified: {architecture_data.components}")
        
    except (json.JSONDecodeError, KeyError, Exception) as e:
        print(f"❌ Error during diagram processing/validation: {e}")
        return

    # 2B. Threat Research (Calls the CVEResearchTool)
    print("\n✅ STEP 2: Calling Threat Research Tool (NVD/CISA KEV)...")
    
    research_tool_func = planner_agent.tools[1].func
    # Use the components found in the previous step
    raw_threats_json = research_tool_func(None, architecture_data.components)
    
    try:
        # Validate and convert the JSON output
        raw_threats = ThreatSearchResults.model_validate_json(raw_threats_json)
        print(f"   -> Found {len(raw_threats.threats)} raw threats.")
        
    except json.JSONDecodeError:
        print("❌ Error decoding threat search results. API may have failed.")
        return

    # 2C. Risk Assessment & Final Report (Executes the Assessment Agent)
    print("\n✅ STEP 3: Executing Risk Assessment Agent (Contextual Reasoning)...")
    
    # The Planner delegates the data to the Assessment Agent via the run_assessment function
    final_report_json = run_assessment(assessment_agent, architecture_data, raw_threats)
    
    try:
        FinalReport.model_validate_json(final_report_json)
        print("   -> Assessment complete and report validated.")
    except Exception as e:
        print(f"❌ Assessment Agent failed to return valid structured JSON: {e}")
        print("Raw Assessment Output (for debugging):", final_report_json[:500] + "...")
        return
        
    # 2D. Synthesis (Planner Agent's Final Task)
    print("\n✅ STEP 4: Planner Agent synthesizes final report...")
    
    synthesis_prompt = f"""
    The full, structured risk assessment has been completed. Synthesize the following 
    structured JSON report into a professional, narrative-driven Threat Model Summary 
    for an executive audience. Focus on the CRITICAL and HIGH severity threats first.
    
    STRUCTURED REPORT:
    {final_report_json}
    """
    
    final_narrative_response = planner_agent.generate_content(synthesis_prompt)
    
    print("\n\n" + "=" * 50)
    print("🛡️ FINAL THREAT MODEL REPORT (EXECUTIVE SUMMARY)")
    print("=" * 50)
    print(final_narrative_response.text)
    print("=" * 50)


if __name__ == "__main__":
    # Use argparse to accept the image path via command line
    parser = argparse.ArgumentParser(description="Run the Threat Modeling Agent Capstone Project.")
    parser.add_argument(
        "image_path", 
        type=str, 
        help="Path to the system architecture diagram image (e.g., data/my_test_arch.png)"
    )
    args = parser.parse_args()
    
    # Check for API Key before running
    if not os.getenv("GEMINI_API_KEY"):
        print("\nFATAL ERROR: The GEMINI_API_KEY environment variable is not set.")
        print("Please set the key using: $env:GEMINI_API_KEY='YOUR_KEY'")
    else:
        try:
            main(args.image_path)
        except Exception as e:
            # Catching top-level exceptions for better visibility than a silent crash
            print("\n" + "="*50)
            print(f"UNEXPECTED TOP-LEVEL ERROR: {type(e).__name__}")
            print(f"DETAILS: {e}")
            print("="*50)