import urllib.parse
import httpx
import asyncio

async def test_openapi():
    target_url = "http://localhost:8080"
    url = urllib.parse.urljoin(target_url, "/openapi.json")
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
        print(f"Status: {resp.status_code}")
        data = resp.json()
        print(f"Has paths? {'paths' in data}")
        for path, methods in data["paths"].items():
            print(f"Path: {path}")
            for method, details in methods.items():
                print(f"Method: {method}")
                params = []
                for param in details.get("parameters", []):
                    name = param.get("name")
                    loc = param.get("in", "query")
                    ptype = param.get("schema", {}).get("type", "string")
                    print(f"Param: {name}, Loc: {loc}, Type: {ptype}")

asyncio.run(test_openapi())
