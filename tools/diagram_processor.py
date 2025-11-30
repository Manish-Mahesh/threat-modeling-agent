import os
from google import genai
from google.genai import types
from google.adk.tools import ToolContext
from tools.models import ArchitectureSchema # Import the Pydantic schema
from tenacity import retry, stop_after_attempt, wait_exponential

# NOTE: The GEMINI_API_KEY environment variable must be set for this to work.

@retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=4, max=10))
def _generate_content_with_retry(client, model, contents, config):
    return client.models.generate_content(
        model=model,
        contents=contents,
        config=config
    )

def process_architecture_diagram(tool_context: ToolContext, image_path: str) -> dict:
    """
    Analyzes a system architecture diagram image to extract structured component, 
    data flow, and trust boundary information.
    
    This tool uses a multimodal Gemini model to identify the system's architecture 
    and returns the details as a structured JSON object for reliable agent processing.
    
    Args:
        image_path: The local file path to the architecture diagram image (e.g., 'data/test_arch.png').
        
    Returns:
        A dictionary representation of the ArchitectureSchema JSON object.
    """
    try:
        # 1. Initialize the client
        # The client automatically picks up the GEMINI_API_KEY environment variable.
        client = genai.Client()
        
        # 2. Load the image file as a Part for the API call
        with open(image_path, "rb") as f:
            # We assume a common image type like PNG or JPEG
            image_part = types.Part.from_bytes(data=f.read(), mime_type='image/png')
            
        # 3. Define the multimodal prompt
        prompt = f"""
        Analyze the uploaded system architecture diagram. Your task is to identify and list 
        all software components, their versions (if labeled), describe the data flow, 
        and identify all trust boundaries or security zones shown.
        
        You MUST respond with a single JSON object that strictly conforms to the 
        ArchitectureSchema defined in the response_schema. 
        DO NOT include any conversational text, explanations, or code fences outside the JSON block.
        """

        # 4. Call the Vision model with structured output configuration
        response = _generate_content_with_retry(
            client,
            model='gemini-2.0-flash', # Use a multimodal model
            contents=[prompt, image_part],
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=ArchitectureSchema, # Enforce the Pydantic schema
            ),
        )
        
        # The response.text is the JSON string conforming to ArchitectureSchema
        return response.text 
    
    except FileNotFoundError:
        return {"error": f"File not found at path: {image_path}"}
    except Exception as e:
        # Important for robustness (Day 4: Quality)
        return {"error": f"Failed to process diagram with Gemini: {e}"}