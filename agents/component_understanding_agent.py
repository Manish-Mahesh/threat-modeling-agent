"""
ComponentUnderstandingAgent
Infers real technology categories from raw architecture labels using heuristics and LLM reasoning.
"""
from typing import List, Dict, Any, Optional
import os
import re
import time
import logging
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from tools.threat_intel_api import _looks_like_software_identifier

# Configure logging
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
MAX_RETRIES = 3
BASE_DELAY = 2.0
CONCURRENCY_LIMIT = 2 # Limit parallel requests if we were using async, but here we batch.
PRIMARY_MODEL = "gemini-3-pro-preview"
FALLBACK_MODEL = "gemini-2.0-flash-exp" # Faster/cheaper fallback if available

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

class ComponentInferenceItem(BaseModel):
    component_name: str = Field(description="The exact name of the component from the input list.")
    inference: ProductInference

class BatchInferenceResult(BaseModel):
    results: List[ComponentInferenceItem]

class ComponentUnderstandingAgent:
    """
    Accepts raw component labels and infers likely technology categories.
    Output: list of dicts with component_name, inferred_product_categories, confidence
    """
    def __init__(self):
        self.client = None
        if os.getenv("GEMINI_API_KEY"):
             self.client = genai.Client()

    def _call_llm_with_retry(self, prompt: str, schema: Any, model: str = PRIMARY_MODEL) -> Any:
        """
        Helper to call LLM with retries and exponential backoff.
        """
        if not self.client:
            return None

        attempt = 0
        while attempt < MAX_RETRIES:
            try:
                response = self.client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=schema,
                    ),
                )
                return response
            except Exception as e:
                attempt += 1
                logger.warning(f"LLM call failed (Attempt {attempt}/{MAX_RETRIES}): {e}")
                if attempt >= MAX_RETRIES:
                    # If primary model fails, try fallback once if configured and different
                    if model == PRIMARY_MODEL and FALLBACK_MODEL and FALLBACK_MODEL != PRIMARY_MODEL:
                        logger.info(f"Falling back to model {FALLBACK_MODEL}...")
                        return self._call_llm_with_retry(prompt, schema, model=FALLBACK_MODEL)
                    raise e
                
                # Exponential backoff
                sleep_time = BASE_DELAY * (2 ** (attempt - 1))
                time.sleep(sleep_time)
        return None

    def _infer_batch_with_llm(self, target_components: List[str], all_components: List[str]) -> Dict[str, ProductInference]:
        """
        Batched inference for multiple components in a single LLM call.
        """
        if not self.client or not target_components:
            return {}

        prompt = f"""
        You are a security architect analyzing a system architecture.
        The system contains the following components: {all_components}.
        
        For each of the following generic components, infer the most likely specific technology product 
        based on the context of the other components (e.g., if 'Django' is present, a 'Database' is likely 'PostgreSQL').
        
        Components to analyze: {target_components}
        
        Return a JSON list of results. 
        If you cannot infer a specific product with > 50% confidence for a component, return "Generic" as the product for that item.
        """
        
        try:
            # Call LLM with retry logic
            response = self._call_llm_with_retry(prompt, BatchInferenceResult)
            
            if not response:
                return {}

            batch_result = BatchInferenceResult.model_validate_json(response.text)
            
            # Map results back to component names
            inference_map = {}
            for item in batch_result.results:
                inference_map[item.component_name] = item.inference
            
            return inference_map

        except Exception as e:
            logger.error(f"Batch LLM Inference failed: {e}")
            return {}

    def infer_components(self, raw_labels: List[str]) -> List[Dict[str, Any]]:
        results = []
        
        # 1. Identify which components need LLM inference (generic ones)
        generic_components = []
        for label in raw_labels:
            if not _looks_like_software_identifier(label):
                generic_components.append(label)
        
        # 2. Perform Batch Inference
        batch_inferences = {}
        if generic_components and self.client:
            print(f"   ... Batch inferring products for {len(generic_components)} generic components...")
            batch_inferences = self._infer_batch_with_llm(generic_components, raw_labels)

        # 3. Process all components
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
            
            # Check if we have an LLM inference for this component
            if label in batch_inferences:
                inference = batch_inferences[label]
                if inference.suggested_product.lower() != "generic" and inference.confidence > 0.6:
                    inferred.append(inference.suggested_product.lower())
                    print(f"      -> Inferred '{inference.suggested_product}' for '{label}' (Confidence: {inference.confidence})")
            
            # Remove duplicates
            inferred = list(set(inferred))
            confidence = score_confidence(label_lower, inferred)
            results.append({
                "component_name": label,
                "inferred_product_categories": inferred,
                "confidence": confidence
            })
            
        return results
