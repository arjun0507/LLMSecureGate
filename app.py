import os
from pathlib import Path
from typing import Dict, List

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from securegate.observability import METRICS
from securegate.pipeline import SecureGatePipeline

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

load_dotenv()

app = FastAPI(title="LLM Chat App", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    reply: str
    original_prompt: str = ""
    sanitized_prompt: str = ""
    raw_reply: str = ""
    sanitized_reply: str = ""
    inbound_risk_score: float = 0.0
    outbound_risk_score: float = 0.0
    inbound_flags: List[Dict[str, object]] = Field(default_factory=list)
    outbound_flags: List[Dict[str, str]] = Field(default_factory=list)
    inbound_actions: List[str] = Field(default_factory=list)
    outbound_actions: List[str] = Field(default_factory=list)
    model_score: float = 0.0
    semantic_leakage_score: float = 0.0
    transformer_score: float = 0.0
    detected_entities: List[str] = Field(default_factory=list)
    explanations: Dict[str, str] = Field(default_factory=dict)
    latency_ms: Dict[str, float] = Field(default_factory=dict)


def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value is not None and value != "" else default


async def _chat_via_ollama(message: str) -> str:
    """
    Uses a locally running Ollama server (free, on-device).
    Ollama API docs: /api/chat on http://localhost:11434 by default.
    """
    base_url = _env("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    model = _env("OLLAMA_MODEL", "llama3.2")
    system_prompt = _env("SYSTEM_PROMPT", "You are a helpful assistant.")

    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": message},
        ],
        "options": {
            "num_predict": 512,  # Limit response length for faster generation
            "temperature": 0.7,  # Balanced temperature
            "top_p": 0.9,  # Nucleus sampling
        }
    }

    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            res = await client.post(f"{base_url}/api/chat", json=payload)
            res.raise_for_status()
            data = res.json()
    except httpx.ConnectError as e:
        raise RuntimeError(
            "Couldn't connect to Ollama. Install Ollama and make sure it's running, "
            "then pull a model (e.g. 'ollama pull llama3.2')."
        ) from e
    except httpx.HTTPStatusError as e:
        detail = ""
        try:
            detail = e.response.json().get("error", "")  # type: ignore[assignment]
        except Exception:
            detail = e.response.text
        raise RuntimeError(f"Ollama error: {detail or e.response.status_code}") from e

    reply = (data.get("message") or {}).get("content") or ""
    return str(reply).strip()


securegate_pipeline = SecureGatePipeline()

# Cache for examples to avoid loading database on every request
_examples_cache = None


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/metrics")
async def metrics() -> Dict[str, Dict[str, int]]:
    return {"counters": METRICS.snapshot()}


@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    try:
        provider = _env("LLM_PROVIDER", "ollama").lower()
        if provider != "ollama":
            raise RuntimeError(
                "This project is configured for free local LLMs via Ollama. "
                "Set LLM_PROVIDER=ollama (or remove it) to use the default."
            )

        gate_result = await securegate_pipeline.process(
            prompt=request.message,
            llm_callable=_chat_via_ollama,
        )
        return ChatResponse(
            reply=gate_result.final_reply,
            original_prompt=gate_result.prompt_result.original_prompt,
            sanitized_prompt=gate_result.prompt_result.sanitized_prompt,
            raw_reply=gate_result.response_result.raw_reply,
            sanitized_reply=gate_result.response_result.sanitized_reply,
            inbound_risk_score=gate_result.prompt_result.risk_score,
            outbound_risk_score=gate_result.response_result.risk_score,
            inbound_flags=SecureGatePipeline.serialize_flags(gate_result.prompt_result),
            outbound_flags=SecureGatePipeline.serialize_redactions(gate_result.response_result),
            inbound_actions=gate_result.prompt_result.actions,
            outbound_actions=gate_result.response_result.actions,
            model_score=gate_result.prompt_result.model_score,
            semantic_leakage_score=gate_result.prompt_result.semantic_leakage_score,
            transformer_score=getattr(gate_result.prompt_result, 'transformer_score', 0.0),
            detected_entities=gate_result.response_result.detected_entities,
            explanations=gate_result.explanations,
            latency_ms=gate_result.timings.as_dict(),
        )
    except RuntimeError as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:  # pragma: no cover - generic fallback
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"LLM request failed: {str(e)}") from e


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def index() -> FileResponse:
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not found.")
    return FileResponse(str(index_path))


@app.get("/api/examples")
async def get_examples():
    """Get prompt examples for testing"""
    global _examples_cache

    # Return cached examples if available
    if _examples_cache is not None:
        return _examples_cache

    from ui.prompt_examples import get_prompt_examples_db

    examples_db = get_prompt_examples_db()

    # Return all malicious and benign examples
    malicious_examples = examples_db.get_malicious_examples()
    benign_examples = examples_db.get_benign_examples()

    result = {
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

    # Cache the result
    _examples_cache = result
    return result


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
        gate_result = await securegate_pipeline.process(
            prompt,
            lambda p: None  # No actual LLM call for testing
        )

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
