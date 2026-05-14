"""Verify new examples are loaded"""
import httpx
import asyncio

async def test():
    async with httpx.AsyncClient() as client:
        response = await client.get('http://127.0.0.1:8000/api/examples')
        data = response.json()
        malicious = data.get('malicious', [])
        print(f'Total malicious examples: {len(malicious)}')
        print()
        
        # Show advanced jailbreak examples
        advanced = [e for e in malicious if 'advanced_jailbreak' in e.get('tags', [])]
        print(f'Advanced jailbreak examples: {len(advanced)}')
        for e in advanced:
            print(f"  - {e['category']}: {e['description'][:50]}...")
        print()
        
        # Show output sanitization examples
        sanitization = [e for e in malicious if 'output_sanitization' in e.get('tags', [])]
        print(f'Output sanitization test examples: {len(sanitization)}')
        for e in sanitization:
            print(f"  - {e['description'][:50]}...")

asyncio.run(test())
