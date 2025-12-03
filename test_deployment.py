import os
import vertexai
from vertexai.preview import reasoning_engines
from dotenv import load_dotenv
import json

# Load environment variables
load_dotenv()

# Configuration
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT") or "gen-lang-client-0500458343"
LOCATION = "us-central1"

def test_agent():
    print(f"🔄 Initializing Vertex AI for project {PROJECT_ID} in {LOCATION}...")
    vertexai.init(project=PROJECT_ID, location=LOCATION)

    print("🔍 Listing deployed agents...")
    try:
        # List all reasoning engines
        agents = reasoning_engines.ReasoningEngine.list()
    except Exception as e:
        print(f"❌ Error listing agents: {e}")
        return
    
    if not agents:
        print("❌ No deployed agents found.")
        return

    # Try to find the specific agent we deployed (sort by update time if possible, or just pick the first matching name)
    target_agent = None
    # Filter by display name
    matching_agents = [a for a in agents if a.display_name == "threat-modeling-agent-v1"]
    
    if matching_agents:
        # Pick the last one (assuming list returns in some order, or just pick one)
        # Ideally we'd sort by create_time but that might require parsing strings.
        # Let's just pick the first one found in the list, which is usually the most recent or relevant.
        target_agent = matching_agents[0] 
    else:
        print("⚠️ Could not find agent with name 'threat-modeling-agent-v1', using the first available agent.")
        target_agent = agents[0]

    print(f"✅ Found agent: {target_agent.resource_name}")
    print(f"   Display Name: {target_agent.display_name}")

    # Re-instantiate the agent client using the resource name to ensure dynamic methods are available
    print("   Connecting to agent client...")
    agent_client = reasoning_engines.ReasoningEngine(target_agent.resource_name)

    # Test Data (Simple JSON input representing a basic architecture)
    test_input = {
        "project_name": "Test Web App",
        "description": "A simple web server connecting to a database.",
        "components": [
            {"name": "Nginx Web Server", "type": "Web Server"},
            {"name": "PostgreSQL Database", "type": "Database"}
        ],
        "data_flows": [
            {"source": "Nginx Web Server", "destination": "PostgreSQL Database", "protocol": "TCP/5432"}
        ],
        "trust_boundaries": ["Internet Boundary"]
    }
    
    json_str = json.dumps(test_input)

    print("\n🧪 Sending test query to agent...")
    print(f"   Input: {json_str}")
    
    try:
        # The query method matches the signature defined in vertex_entrypoint
        response = agent_client.query(input=test_input)
        
        # Handle response object or string
        output = getattr(response, "output_text", response)
        
        print("\n✅ Agent Response Received:")
        print("=" * 50)
        print(output)
        print("=" * 50)
    except Exception as e:
        print(f"\n❌ Error querying agent: {e}")

if __name__ == "__main__":
    test_agent()
