#!/usr/bin/env python3
"""
Test script to debug Ollama integration issues
"""

import asyncio
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


async def test_ollama_direct():
    """Test direct Ollama API call"""
    import httpx
    
    print("Testing direct Ollama API call...")
    
    base_url = "http://127.0.0.1:11434"
    model = "llama3.2"
    system_prompt = "You are a helpful assistant."
    message = "What are best practices for API security?"
    
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
        
        reply = (data.get("message") or {}).get("content") or ""
        print(f"✓ Direct Ollama call successful!")
        print(f"Reply: {reply[:200]}...")
        return True
        
    except Exception as e:
        print(f"✗ Direct Ollama call failed: {e}")
        return False


async def test_securegate_pipeline():
    """Test SecureGate pipeline"""
    print("\nTesting SecureGate pipeline...")
    
    try:
        from app import _chat_via_ollama
        reply = await _chat_via_ollama("What are best practices for API security?")
        print(f"✓ SecureGate pipeline successful!")
        print(f"Reply: {reply[:200]}...")
        return True
        
    except Exception as e:
        print(f"✗ SecureGate pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_full_securegate():
    """Test full SecureGate process"""
    print("\nTesting full SecureGate process...")
    
    try:
        from securegate.pipeline import SecureGatePipeline
        from app import _chat_via_ollama
        
        pipeline = SecureGatePipeline()
        result = await pipeline.process(
            prompt="What are best practices for API security?",
            llm_callable=_chat_via_ollama,
        )
        
        print(f"✓ Full SecureGate process successful!")
        print(f"Final reply: {result.final_reply[:200]}...")
        print(f"Risk score: {result.prompt_result.risk_score}")
        print(f"Blocked: {result.prompt_result.blocked}")
        return True
        
    except Exception as e:
        print(f"✗ Full SecureGate process failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Run all tests"""
    print("=== Ollama Integration Debug ===\n")
    
    tests = [
        test_ollama_direct,
        test_securegate_pipeline,
        test_full_securegate,
    ]
    
    results = []
    for test in tests:
        try:
            result = await test()
            results.append(result)
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
            results.append(False)
    
    print(f"\n=== Summary ===")
    print(f"Direct Ollama: {'✓' if results[0] else '✗'}")
    print(f"SecureGate Pipeline: {'✓' if results[1] else '✗'}")
    print(f"Full SecureGate: {'✓' if results[2] else '✗'}")


if __name__ == "__main__":
    asyncio.run(main())
