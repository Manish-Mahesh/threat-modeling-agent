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
from tools.threat_intel_api import search_vulnerabilities, search_vulnerabilities_json

# Import Data Models for Validation
from tools.models import ArchitectureSchema, ThreatSearchResults, FinalReport


def main(image_path: str = None, json_input: str = None):
    """
    Initializes and orchestrates the Threat Modeling Multi-Agent System.
    """
    
    print("🤖 Initializing Multi-Agent Threat Modeling Pipeline...")
    print("-" * 50)
    
    architecture_data = None

    if json_input:
        print(f"\n▶️ Starting Threat Modeling Workflow from JSON input: {json_input}")
        try:
            with open(json_input, 'r') as f:
                data = json.load(f)
            # If the JSON is the raw output from the diagram processor (string), parse it
            if isinstance(data, str):
                architecture_data = ArchitectureSchema.model_validate_json(data)
            else:
                # If it's already a dict matching the schema
                architecture_data = ArchitectureSchema.model_validate(data)
            print("   -> Architecture data loaded and validated.")
            print(f"   -> Components identified: {architecture_data.components}")
        except Exception as e:
            print(f"❌ Error loading JSON input: {e}")
            return
    elif image_path:
        print(f"\n▶️ Starting Threat Modeling Workflow for image: {image_path}")
        # 1. Vision Agent: Extract raw component labels from diagram
        from tools.diagram_processor import process_architecture_diagram
        diagram_data_json = process_architecture_diagram(None, image_path)
        try:
            architecture_data = ArchitectureSchema.model_validate_json(diagram_data_json)
            print("   -> Architecture data extracted and validated.")
            print(f"   -> Components identified: {architecture_data.components}")
        except Exception as e:
            print(f"❌ Error during diagram processing/validation: {e}")
            return
    else:
        print("❌ Error: Must provide either --image or --input (JSON).")
        return

    # 2. Component Understanding Agent: Infer real technologies
    from agents.component_understanding_agent import ComponentUnderstandingAgent
    comp_agent = ComponentUnderstandingAgent()
    # Extract component names for inference
    component_names = [c.name for c in architecture_data.components]
    inferred_components = comp_agent.infer_components(component_names)
    print("   -> Inferred component technologies:")
    for comp in inferred_components:
        print(f"      {comp['component_name']}: {comp['inferred_product_categories']} (confidence={comp['confidence']})")

    # 3. Threat Knowledge Agent: Generate generic threats
    from agents.threat_knowledge_agent import ThreatKnowledgeAgent
    threat_agent = ThreatKnowledgeAgent()
    # Updated to pass architecture_data for STRIDE analysis
    generic_threats = threat_agent.generate_threats(inferred_components, architecture_data)
    print(f"   -> Generated {len(generic_threats)} generic architectural threats.")

    # 4. CVE Discovery Agent: Query NVD/CISA for relevant product types
    from agents.cve_discovery_agent import CVEDiscoveryAgent
    cve_agent = CVEDiscoveryAgent()
    cve_threats = cve_agent.discover_cves(inferred_components)
    print(f"   -> Discovered {len(cve_threats)} raw CVEs.")

    # 5. Threat Relevance Agent: Match and filter threats
    from agents.threat_relevance_agent import ThreatRelevanceAgent
    relevance_agent = ThreatRelevanceAgent()
    match_results = relevance_agent.match_relevant_threats(inferred_components, generic_threats, cve_threats)
    print(f"   -> {len(match_results['relevant_threats'])} relevant architectural threats, {len(match_results['relevant_cves'])} relevant CVEs.")

    # 6. Report Synthesizer Agent: Generate final report
    from agents.report_synthesizer_agent import ReportSynthesizerAgent
    report_agent = ReportSynthesizerAgent()
    # Updated to pass architecture_data for full context
    final_report = report_agent.synthesize_report(match_results, architecture_data)

    # Generate Markdown Report
    markdown_report = report_agent.generate_markdown_report(final_report)
    report_filename = "threat_report.md"
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(markdown_report)
    print(f"\n✅ Report saved to {report_filename}")

    print("\n\n" + "=" * 50)
    print("🛡️ FINAL THREAT MODEL REPORT (EXECUTIVE SUMMARY)")
    print("=" * 50)
    print(final_report["executive_summary"])
    
    print("\n" + "-" * 30)
    print("🔥 Threat Summary")
    print("-" * 30)
    print(f"Architectural Threats: {len(final_report['threats'])}")
    print(f"Specific CVEs: {len(final_report['cves'])}")
    
    print("\n" + "-" * 30)
    print("🛡️ Recommended Hardening (NIST 800-53)")
    print("-" * 30)
    
    # Simple preview of mitigations
    count = 0
    for item in final_report["cves"]:
        mit = item["cve"].mitigation
        if mit and count < 5:
            print(f"✅ {mit.primary_fix}")
            if mit.nist_controls:
                print(f"   (Controls: {', '.join(mit.nist_controls)})")
            count += 1
    if count == 0:
        print("No specific mitigations generated.")
        
    print("=" * 50)


if __name__ == "__main__":
    # Use argparse to accept the image path via command line
    parser = argparse.ArgumentParser(description="Run the Threat Modeling Agent Capstone Project.")
    parser.add_argument(
        "--image", 
        type=str, 
        help="Path to the system architecture diagram image (e.g., data/my_test_arch.png)"
    )
    parser.add_argument(
        "--input", 
        type=str, 
        help="Path to a JSON file containing architecture data (skips image processing)"
    )
    args = parser.parse_args()
    
    # Check for API Key before running
    if not os.getenv("GEMINI_API_KEY"):
        print("\nFATAL ERROR: The GEMINI_API_KEY environment variable is not set.")
        print("Please set the key using: $env:GEMINI_API_KEY='YOUR_KEY'")
    else:
        try:
            main(image_path=args.image, json_input=args.input)
        except Exception as e:
            # Catching top-level exceptions for better visibility than a silent crash
            print("\n" + "="*50)
            print(f"UNEXPECTED TOP-LEVEL ERROR: {type(e).__name__}")
            print(f"DETAILS: {e}")
            print("="*50)