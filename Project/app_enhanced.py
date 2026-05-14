"""
Enhanced FastAPI Application with Improved UI

This provides an enhanced FastAPI application with the new web interface,
better error handling, and improved user experience.
"""

import os
import time
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional

import httpx
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Import SecureGate components
from securegate.pipeline import SecureGatePipeline
from securegate.production_integration import get_production_pipeline, get_production_health
from securegate.model_monitor import get_model_monitor


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000, description="The message to send to the AI")
    temperature: Optional[float] = Field(0.7, ge=0.0, le=2.0, description="Temperature for response generation")
    max_tokens: Optional[int] = Field(1000, ge=1, le=4000, description="Maximum tokens in response")


class ChatResponse(BaseModel):
    reply: str = ""
    original_prompt: str = ""
    sanitized_prompt: str = ""
    raw_reply: str = ""
    sanitized_reply: str = ""
    inbound_risk_score: float = 0.0
    outbound_risk_score: float = 0.0
    inbound_flags: List[Dict[str, Any]] = Field(default_factory=list)
    outbound_flags: List[Dict[str, str]] = Field(default_factory=list)
    inbound_actions: List[str] = Field(default_factory=list)
    outbound_actions: List[str] = Field(default_factory=list)
    model_score: float = 0.0
    semantic_leakage_score: float = 0.0
    transformer_score: float = 0.0
    detected_entities: List[str] = Field(default_factory=list)
    explanations: Dict[str, str] = Field(default_factory=dict)
    latency_ms: Dict[str, float] = Field(default_factory=dict)
    request_id: str = ""
    timestamp: str = ""


class HealthResponse(BaseModel):
    status: str = "ok"
    timestamp: str = ""
    version: str = "1.0.0"
    components: Dict[str, str] = Field(default_factory=dict)


class MetricsResponse(BaseModel):
    timestamp: str = ""
    total_requests: int = 0
    blocked_requests: int = 0
    avg_risk_score: float = 0.0
    avg_response_time: float = 0.0
    model_performance: Dict[str, float] = Field(default_factory=dict)
    system_health: Dict[str, bool] = Field(default_factory=dict)


# Initialize FastAPI app
app = FastAPI(
    title="SecureGate Enhanced",
    description="AI Security Gateway with Enhanced UI",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Global variables
pipeline: Optional[SecureGatePipeline] = None
production_pipeline = None
request_count = 0
blocked_count = 0
total_risk_score = 0.0
total_response_time = 0.0


@app.on_event("startup")
async def startup_event():
    """Initialize the application"""
    global pipeline, production_pipeline
    
    print("🚀 Starting SecureGate Enhanced Application...")
    
    # Initialize pipelines
    pipeline = SecureGatePipeline()
    production_pipeline = get_production_pipeline()
    
    print("✅ SecureGate pipelines initialized")
    print("🌐 Enhanced UI ready at http://localhost:8000")
    print("📊 Dashboard available at http://localhost:8501")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    print("🛑 Shutting down SecureGate Enhanced Application...")


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the enhanced chat interface"""
    try:
        with open("templates/enhanced_chat.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="""
        <html>
            <head><title>SecureGate Enhanced</title></head>
            <body>
                <h1>SecureGate Enhanced</h1>
                <p>Enhanced UI template not found. Please check templates directory.</p>
                <p><a href="/docs">API Documentation</a></p>
            </body>
        </html>
        """)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    try:
        # Get production health
        production_health = get_production_health()
        
        # Check individual components
        components = {
            "api": "healthy",
            "pipeline": "healthy" if pipeline else "unhealthy",
            "production": "healthy" if production_health.get("overall", False) else "unhealthy",
            "monitoring": "healthy"
        }
        
        # Overall status
        overall_status = "healthy" if all(status == "healthy" for status in components.values()) else "unhealthy"
        
        return HealthResponse(
            status=overall_status,
            timestamp=datetime.now().isoformat(),
            components=components
        )
        
    except Exception as e:
        return HealthResponse(
            status="unhealthy",
            timestamp=datetime.now().isoformat(),
            components={"error": str(e)}
        )


@app.get("/metrics", response_model=MetricsResponse)
async def get_metrics():
    """Get system metrics"""
    global request_count, blocked_count, total_risk_score, total_response_time
    
    try:
        # Get model monitor metrics
        model_monitor = get_model_monitor()
        performance_summary = model_monitor.get_performance_summary()
        
        # Calculate averages
        avg_risk_score = total_risk_score / max(request_count, 1)
        avg_response_time = total_response_time / max(request_count, 1)
        
        # Get system health
        system_health = get_production_health()
        
        return MetricsResponse(
            timestamp=datetime.now().isoformat(),
            total_requests=request_count,
            blocked_requests=blocked_count,
            avg_risk_score=avg_risk_score,
            avg_response_time=avg_response_time,
            model_performance=performance_summary.get("current_metrics", {}),
            system_health=system_health
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {str(e)}")


@app.post("/api/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest):
    """Enhanced chat endpoint with comprehensive monitoring"""
    global request_count, blocked_count, total_risk_score, total_response_time
    
    start_time = time.perf_counter()
    request_id = f"req_{int(time.time() * 1000)}"
    
    try:
        # Use production pipeline if available
        if production_pipeline:
            # Evaluate with monitoring
            result, inference_time = production_pipeline.evaluate_prompt_with_monitoring(
                request.message, 
                actual_label=None  # We don't have ground truth in production
            )
            
            # Process through LLM if not blocked
            if not result.get("blocked", False):
                try:
                    raw_reply = await _chat_via_ollama(result.get("sanitized_prompt", request.message))
                    gate_result = await pipeline.process(
                        result.get("sanitized_prompt", request.message),
                        lambda prompt: asyncio.create_task(asyncio.sleep(0, raw_reply))
                    )
                    response_result = gate_result.response_result
                except Exception as e:
                    # Fallback response if LLM fails
                    raw_reply = "I apologize, but I'm unable to process this request at the moment."
                    response_result = pipeline.response_engine.sanitize(raw_reply)
            else:
                # Blocked - use safe refusal
                raw_reply = "I cannot process this request as it violates security policies."
                response_result = pipeline.response_engine.sanitize(raw_reply)
            
            # Create response
            response = ChatResponse(
                reply=response_result.sanitized_reply,
                original_prompt=request.message,
                sanitized_prompt=result.get("sanitized_prompt", request.message),
                raw_reply=raw_reply,
                sanitized_reply=response_result.sanitized_reply,
                inbound_risk_score=result.get("risk_score", 0.0),
                outbound_risk_score=response_result.risk_score,
                inbound_flags=[{"label": flag.label, "evidence": flag.evidence, "severity": flag.severity} 
                            for flag in []],  # Would be populated from actual result
                outbound_flags=[{"label": redaction.label, "match": redaction.match, "replacement": redaction.replacement}
                             for redaction in response_result.redactions],
                inbound_actions=result.get("actions", []),
                outbound_actions=response_result.actions,
                model_score=result.get("model_score", 0.0),
                semantic_leakage_score=result.get("semantic_score", 0.0),
                transformer_score=result.get("transformer_score", 0.0),
                detected_entities=response_result.detected_entities,
                explanations={},  # Would be populated from actual result
                latency_ms={
                    "prompt_defense_ms": inference_time * 1000,
                    "llm_ms": 0.0,  # Would be measured
                    "response_sanitization_ms": 0.0,  # Would be measured
                    "total_ms": (time.perf_counter() - start_time) * 1000
                },
                request_id=request_id,
                timestamp=datetime.now().isoformat()
            )
            
        else:
            # Fallback to original pipeline
            gate_result = await pipeline.process(
                request.message,
                lambda prompt: _chat_via_ollama(prompt)
            )
            
            response = ChatResponse(
                reply=gate_result.response_result.sanitized_reply,
                original_prompt=gate_result.prompt_result.original_prompt,
                sanitized_prompt=gate_result.prompt_result.sanitized_prompt,
                raw_reply=gate_result.response_result.raw_reply,
                sanitized_reply=gate_result.response_result.sanitized_reply,
                inbound_risk_score=gate_result.prompt_result.risk_score,
                outbound_risk_score=gate_result.response_result.risk_score,
                inbound_flags=[{"label": flag.label, "evidence": flag.evidence, "severity": flag.severity} 
                            for flag in gate_result.prompt_result.flags],
                outbound_flags=[{"label": redaction.label, "match": redaction.match, "replacement": redaction.replacement}
                             for redaction in gate_result.response_result.redactions],
                inbound_actions=gate_result.prompt_result.actions,
                outbound_actions=gate_result.response_result.actions,
                model_score=gate_result.prompt_result.model_score,
                semantic_leakage_score=gate_result.prompt_result.semantic_leakage_score,
                transformer_score=getattr(gate_result.prompt_result, 'transformer_score', 0.0),
                detected_entities=gate_result.response_result.detected_entities,
                explanations=gate_result.explanations,
                latency_ms=gate_result.timings.as_dict(),
                request_id=request_id,
                timestamp=datetime.now().isoformat()
            )
        
        # Update metrics
        request_count += 1
        total_risk_score += response.inbound_risk_score
        total_response_time += (time.perf_counter() - start_time) * 1000
        
        if response.sanitized_prompt != response.original_prompt:
            blocked_count += 1
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat processing failed: {str(e)}")


async def _chat_via_ollama(message: str) -> str:
    """Chat with Ollama LLM"""
    base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3.2")
    system_prompt = os.getenv("SYSTEM_PROMPT", "You are a helpful assistant.")
    
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": message},
        ],
    }
    
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            res = await client.post(f"{base_url}/api/chat", json=payload)
            res.raise_for_status()
            data = res.json()
            return (data.get("message") or {}).get("content") or ""
            
    except httpx.ConnectError as e:
        raise RuntimeError(
            "Couldn't connect to Ollama. Install Ollama and make sure it's running, "
            "then pull a model (e.g. 'ollama pull llama3.2')."
        ) from e
    except httpx.HTTPStatusError as e:
        detail = ""
        try:
            error_data = e.response.json()
            detail = error_data.get("error", "")
        except:
            pass
        raise RuntimeError(f"Ollama request failed: {e.response.status_code} {detail}") from e


@app.get("/api/examples")
async def get_examples():
    """Get prompt examples for testing"""
    from ui.prompt_examples import get_prompt_examples_db
    
    examples_db = get_prompt_examples_db()
    
    # Return a mix of malicious and benign examples
    malicious_examples = examples_db.get_malicious_examples()[:5]
    benign_examples = examples_db.get_benign_examples()[:5]
    
    return {
        "malicious": [
            {
                "text": ex.text,
                "category": ex.category.value,
                "difficulty": ex.difficulty,
                "description": ex.description,
                "expected_behavior": ex.expected_behavior,
                "tags": ex.tags
            }
            for ex in malicious_examples
        ],
        "benign": [
            {
                "text": ex.text,
                "category": ex.category.value,
                "difficulty": ex.difficulty,
                "description": ex.description,
                "expected_behavior": ex.expected_behavior,
                "tags": ex.tags
            }
            for ex in benign_examples
        ]
    }


@app.get("/api/examples/categories")
async def get_example_categories():
    """Get all available example categories"""
    from ui.prompt_examples import PromptCategory
    
    return {
        "categories": [category.value for category in PromptCategory],
        "malicious_categories": [cat.value for cat in PromptCategory if "MALICIOUS" in cat.value],
        "benign_categories": [cat.value for cat in PromptCategory if "BENIGN" in cat.value]
    }


@app.post("/api/test-prompt")
async def test_prompt_endpoint(prompt: str):
    """Test a single prompt and return detailed analysis"""
    try:
        if production_pipeline:
            result, inference_time = production_pipeline.evaluate_prompt_with_monitoring(prompt)
            
            return {
                "prompt": prompt,
                "risk_score": result.get("risk_score", 0.0),
                "blocked": result.get("blocked", False),
                "sanitized_prompt": result.get("sanitized_prompt", prompt),
                "model_scores": {
                    "transformer": result.get("transformer_score", 0.0),
                    "ml": result.get("model_score", 0.0),
                    "semantic": result.get("semantic_score", 0.0)
                },
                "inference_time_ms": inference_time * 1000,
                "actions": result.get("actions", []),
                "method": result.get("method", "unknown")
            }
        else:
            # Fallback testing
            gate_result = await pipeline.process(prompt, lambda p: asyncio.create_task(asyncio.sleep(0, "Test response")))
            
            return {
                "prompt": prompt,
                "risk_score": gate_result.prompt_result.risk_score,
                "blocked": gate_result.prompt_result.blocked,
                "sanitized_prompt": gate_result.prompt_result.sanitized_prompt,
                "model_scores": {
                    "transformer": getattr(gate_result.prompt_result, 'transformer_score', 0.0),
                    "ml": gate_result.prompt_result.model_score,
                    "semantic": gate_result.prompt_result.semantic_leakage_score
                },
                "inference_time_ms": gate_result.timings.prompt_defense_ms,
                "actions": gate_result.prompt_result.actions,
                "method": "standard"
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prompt testing failed: {str(e)}")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": str(exc),
            "timestamp": datetime.now().isoformat(),
            "request_id": f"error_{int(time.time() * 1000)}"
        }
    )


if __name__ == "__main__":
    uvicorn.run(
        "app_enhanced:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
