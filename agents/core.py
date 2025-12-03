import os
import json
import tempfile
from typing import Any, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import Agent Factory Functions
from agents.planner_agent import create_planner_agent
from agents.assessment_agent import create_assessment_agent, run_assessment

# Import Custom Tool Functions
from tools.diagram_processor import process_architecture_diagram
from tools.threat_intel_api import search_vulnerabilities, search_vulnerabilities_json

# Import Data Models for Validation
from tools.models import ArchitectureSchema, ThreatSearchResults, FinalReport

# Import Agents
from agents.component_understanding_agent import ComponentUnderstandingAgent
from agents.threat_knowledge_agent import ThreatKnowledgeAgent
from agents.cve_discovery_agent import CVEDiscoveryAgent
from agents.threat_relevance_agent import ThreatRelevanceAgent
from agents.attack_path_agent import AttackPathAgent
from agents.report_synthesizer_agent import ReportSynthesizerAgent


def run_threat_modeling_pipeline(image_path: str = None, json_input: str = None, json_data: dict = None, output_file: str = None):
    """
    Initializes and orchestrates the Threat Modeling Multi-Agent System.
    """
    
    print("🤖 Initializing Multi-Agent Threat Modeling Pipeline...")
    print("-" * 50)
    
    architecture_data = None

    if json_data:
        print(f"\n▶️ Starting Threat Modeling Workflow from provided JSON data.")
        try:
            architecture_data = ArchitectureSchema.model_validate(json_data)
            print("   -> Architecture data loaded and validated.")
            print(f"   -> Components identified: {architecture_data.components}")
        except Exception as e:
            print(f"❌ Error validating JSON data: {e}")
            return

    elif json_input:
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
    comp_agent = ComponentUnderstandingAgent()
    # Extract component names for inference
    component_names = [c.name for c in architecture_data.components]
    inferred_components = comp_agent.infer_components(component_names)
    print("   -> Inferred component technologies:")
    for comp in inferred_components:
        print(f"      {comp['component_name']}: {comp['inferred_product_categories']} (confidence={comp['confidence']})")

    # 3. Threat Knowledge Agent: Generate generic threats
    threat_agent = ThreatKnowledgeAgent()
    # Updated to pass architecture_data for STRIDE analysis
    generic_threats = threat_agent.generate_threats(inferred_components, architecture_data)
    print(f"   -> Generated {len(generic_threats)} generic architectural threats.")

    # 4. CVE Discovery Agent: Query NVD/CISA for relevant product types
    cve_agent = CVEDiscoveryAgent()
    cve_threats = cve_agent.discover_cves(inferred_components)
    print(f"   -> Discovered {len(cve_threats)} raw CVEs.")

    # 5. Threat Relevance Agent: Match and filter threats
    relevance_agent = ThreatRelevanceAgent()
    match_results = relevance_agent.match_relevant_threats(inferred_components, generic_threats, cve_threats)
    print(f"   -> {len(match_results['relevant_threats'])} relevant architectural threats.")
    print(f"   -> {len(match_results.get('relevant_weaknesses', []))} architectural weaknesses.")
    print(f"   -> {len(match_results['relevant_cves'])} relevant CVEs.")

    # 6. Attack Path Agent: Simulate attack paths
    attack_agent = AttackPathAgent()
    print("   -> Simulating attack paths...")
    attack_paths = attack_agent.generate_attack_paths(
        architecture_data, 
        match_results['relevant_threats'], 
        match_results['relevant_cves']
    )
    print(f"   -> Generated {len(attack_paths)} attack paths.")

    # 7. Report Synthesizer Agent: Generate final report
    report_agent = ReportSynthesizerAgent()
    # Updated to pass architecture_data for full context
    final_report = report_agent.synthesize_report(match_results, architecture_data, attack_paths)

    # Generate Markdown Report
    markdown_report = report_agent.generate_markdown_report(final_report)
    
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(markdown_report)
            print(f"\n✅ Report saved to {output_file}")
        except Exception as e:
            print(f"⚠️ Warning: Could not save report to file: {e}")
    
    print("\n\n" + "=" * 50)
    print("🛡️ FINAL THREAT MODEL REPORT (EXECUTIVE SUMMARY)")
    print("=" * 50)
    print(final_report["executive_summary"])
    
    print("\n" + "-" * 30)
    print("🔥 Threat Summary")
    print("-" * 30)
    print(f"Architectural Threats: {len(final_report['threats'])}")
    print(f"Architectural Weaknesses: {len(final_report.get('weaknesses', []))}")
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
    
    return markdown_report


def vertex_entrypoint(
    input: Any = None,
    image_path: Optional[str] = None,
    json_input: Optional[str] = None,
):
    """
    Adapter for Vertex AI Reasoning Engine.

    - Accepts `input` from the ReasoningEngine client.
    - Normalizes it into `image_path` or `json_input`.
    - Calls the existing `run_threat_modeling_pipeline()` function.
    - Returns the markdown string.
    """
    
    # Normalize input into json_input if image_path/json_input are not already provided
    if input is not None and image_path is None and json_input is None:
        if isinstance(input, dict):
            # Treat dict as architecture data, convert to JSON string
            json_content = json.dumps(input)
        elif isinstance(input, str):
            # Assume string is already JSON
            json_content = input
        else:
            return "Error: Invalid input format."
            
        # Create a temporary file for run_threat_modeling_pipeline() to read
        # We use delete=False because we need to close the file before opening it again on Windows
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', encoding='utf-8') as temp:
            temp.write(json_content)
            temp_path = temp.name
            
        try:
            # Call the pipeline with the temp file path
            return run_threat_modeling_pipeline(image_path=image_path, json_input=temp_path, output_file=None)
        finally:
            # Clean up
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

    # Call the pipeline unchanged if no adaptation needed
    return run_threat_modeling_pipeline(image_path=image_path, json_input=json_input, output_file=None)
