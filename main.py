import os
import argparse
from dotenv import load_dotenv
from agents.core import run_threat_modeling_pipeline, vertex_entrypoint

# Load environment variables
load_dotenv()

# Expose vertex_entrypoint for backward compatibility if needed, 
# though deploy_agent.py should now import it from agents.core
__all__ = ['vertex_entrypoint', 'run_threat_modeling_pipeline']

def main(image_path: str = None, json_input: str = None):
    return run_threat_modeling_pipeline(image_path=image_path, json_input=json_input, output_file="threat_report.md")

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