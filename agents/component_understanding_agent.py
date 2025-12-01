"""
ComponentUnderstandingAgent
Infers real technology categories from raw architecture labels using heuristics and LLM reasoning.
"""
from typing import List, Dict, Any, Optional
import os
import re
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from tools.threat_intel_api import _looks_like_software_identifier

# Heuristic mapping for common generic labels to product families
GENERIC_TO_TECH = {
    "production server": ["linux", "web_server", "os"],
    "staging server": ["linux", "web_server", "os"],
    "development server": ["linux", "web_server", "os"],
    "developer computer": ["windows", "os", "developer_machine"],
    "content author computer": ["windows", "os", "developer_machine"],
    "automated deployment infrastructure": ["ci_cd", "pipeline"],
    "database": ["database"],
    "web server": ["web_server"],
    "ci/cd": ["ci_cd", "pipeline"],
    "cloud": ["cloud"],
}

# Simple confidence scoring
def score_confidence(label, inferred):
    if label.lower() in inferred:
        return 1.0
    if any(label.lower() in s for s in inferred):
        return 0.8
    return 0.6

class ProductInference(BaseModel):
    suggested_product: str = Field(description="The specific product name inferred (e.g., 'PostgreSQL', 'Nginx').")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0.")
    reasoning: str = Field(description="Brief explanation for the inference.")

class ComponentUnderstandingAgent:
    """
    Accepts raw component labels and infers likely technology categories.
    Output: list of dicts with component_name, inferred_product_categories, confidence
    """
    def __init__(self):
        self.client = None
        if os.getenv("GEMINI_API_KEY"):
             self.client = genai.Client()

    def _infer_with_llm(self, target_component: str, all_components: List[str]) -> Optional[ProductInference]:
        if not self.client:
            return None
            
        prompt = f"""
        You are a security architect analyzing a system architecture.
        The system contains the following components: {all_components}.
        
        The component '{target_component}' is generic. 
        Based on the other components in the stack (e.g., if 'Django' is present, a 'Database' is likely 'PostgreSQL'), 
        infer the most likely specific technology product for '{target_component}'.
        
        If you cannot infer a specific product with > 50% confidence, return "Generic" as the product.
        """
        
        try:
            response = self.client.models.generate_content(
                model='gemini-3-pro-preview',
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=ProductInference,
                ),
            )
            return ProductInference.model_validate_json(response.text)
        except Exception as e:
            print(f"LLM Inference failed for {target_component}: {e}")
            return None

    def infer_components(self, raw_labels: List[str]) -> List[Dict[str, Any]]:
        results = []
        for label in raw_labels:
            label_lower = label.lower().strip()
            inferred = []
            # Heuristic mapping
            for key, techs in GENERIC_TO_TECH.items():
                if key in label_lower:
                    inferred.extend(techs)
            
            # If label looks like a software identifier, add it
            if _looks_like_software_identifier(label):
                inferred.append(label_lower)
            
            # LLM Inference for generic components
            # If we only have generic tags (like "database") and no specific product
            is_generic = not _looks_like_software_identifier(label)
            if is_generic and self.client:
                print(f"   ... Inferring specific product for generic component '{label}'...")
                inference = self._infer_with_llm(label, raw_labels)
                if inference and inference.suggested_product.lower() != "generic" and inference.confidence > 0.6:
                    inferred.append(inference.suggested_product.lower())
                    print(f"      -> Inferred '{inference.suggested_product}' (Confidence: {inference.confidence})")

            # Remove duplicates
            inferred = list(set(inferred))
            confidence = score_confidence(label_lower, inferred)
            results.append({
                "component_name": label,
                "inferred_product_categories": inferred,
                "confidence": confidence
            })
        return results
