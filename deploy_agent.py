import os
import vertexai
from vertexai.preview import reasoning_engines
from dotenv import load_dotenv
from agents.core import vertex_entrypoint
from typing import Any, Optional

class VertexAdapter:
    def __init__(self, gemini_api_key: str, nvd_api_key: Optional[str] = None):
        self.gemini_api_key = gemini_api_key
        self.nvd_api_key = nvd_api_key

    def set_up(self):
        if self.gemini_api_key:
            os.environ["GEMINI_API_KEY"] = self.gemini_api_key
        if self.nvd_api_key:
            os.environ["NVD_API_KEY"] = self.nvd_api_key

    def query(self, input: Any = None, image_path: Optional[str] = None, json_input: Optional[str] = None):
        # Ensure environment variables are set (fallback if set_up wasn't called)
        if self.gemini_api_key and not os.getenv("GEMINI_API_KEY"):
            os.environ["GEMINI_API_KEY"] = self.gemini_api_key
        if self.nvd_api_key and not os.getenv("NVD_API_KEY"):
            os.environ["NVD_API_KEY"] = self.nvd_api_key
            
        return vertex_entrypoint(input=input, image_path=image_path, json_input=json_input)

# Load environment variables from .env file
load_dotenv()

# --- CONFIGURATION ---
# Replace these with your actual Google Cloud Project details
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT") or "gen-lang-client-0500458343"
LOCATION = "us-central1"  # or your preferred region
STAGING_BUCKET = os.getenv("GCS_STAGING_BUCKET") or "gs://kaggle-staging-ai-agent"

if not PROJECT_ID:
    print("❌ Error: GOOGLE_CLOUD_PROJECT environment variable not set.")
    print("Please run: $env:GOOGLE_CLOUD_PROJECT='your-project-id'")
    exit(1)

if not STAGING_BUCKET:
    print("⚠️ WARNING: GCS_STAGING_BUCKET environment variable not set.")
    print("Please set it using: $env:GCS_STAGING_BUCKET='gs://your-staging-bucket'")
    print("For now, we will try to proceed, but deployment might fail if a default bucket isn't available.")
    # exit(1) # Commented out to allow trying with default or user intervention

print(f"🚀 Deploying Threat Modeling Agent to Vertex AI...")
print(f"   Project: {PROJECT_ID}")
print(f"   Location: {LOCATION}")
print(f"   Staging Bucket: {STAGING_BUCKET}")

# Initialize Vertex AI
if STAGING_BUCKET:
    vertexai.init(project=PROJECT_ID, location=LOCATION, staging_bucket=STAGING_BUCKET)
else:
    vertexai.init(project=PROJECT_ID, location=LOCATION)

# Define requirements
# We need to include all packages used by the app
requirements = [
    "google-genai",
    "google-cloud-aiplatform",
    "pydantic",
    "tenacity",
    "python-dotenv",
    "nvdlib", 
    "requests",
    "python-dateutil",
    "google-adk",
    "cloudpickle>=3.0.0"
]

# Get API keys from local environment to pass to the container
gemini_key = os.getenv("GEMINI_API_KEY")
nvd_key = os.getenv("NVD_API_KEY")

if not gemini_key:
    print("⚠️ WARNING: GEMINI_API_KEY not found in environment. Agent may fail.")

try:
    # Deploy the agent
    remote_agent = reasoning_engines.ReasoningEngine.create(
        reasoning_engine=VertexAdapter(gemini_api_key=gemini_key, nvd_api_key=nvd_key),
        requirements=requirements,
        display_name="threat-modeling-agent-v1",
        description="AI-Powered Multi-Agent Threat Modeling System",
        # Pass environment variables to the container
        extra_packages=["./agents", "./tools"], # Include local packages
    )

    print("\n✅ Deployment Successful!")
    print(f"   Resource Name: {remote_agent.resource_name}")
    
    print("\nTo query the deployed agent:")
    print(f"agent = reasoning_engines.ReasoningEngine('{remote_agent.resource_name}')")
    print("response = agent.query(input={'some': 'json'})")

except Exception as e:
    print(f"\n❌ Deployment Failed: {e}")
