#!/usr/bin/env python3
# test_all_domain_paths.py

import re
import sys
import asyncio

import cloudscraper
from fastapi.testclient import TestClient

# 1. import your FastAPI app (adjust the module path if needed)
from ivi_agent_db import app  

# 2. dummy replacements for any {param} in your routes
DUMMY = {
    "chat_id": "00000000-0000-0000-0000-000000000000",
    "project_id": "demo",
    "user_id": "123",
    # extend as needed…
}

def fill_path(template: str) -> str:
    path = template
    for name, val in DUMMY.items():
        path = path.replace(f"{{{name}}}", val)
    # remove any leftover optional params like '?…'
    return re.sub(r"\{[^}]+\}", "dummy", path)

async def check_route(scraper, method: str, url: str, json_body=None):
    try:
        resp = scraper.request(method, url, json=json_body, timeout=10)
        return resp.status_code, resp.text[:200]
    except Exception as e:
        return f"ERR: {e}", ""

async def main():
    client = TestClient(app)
    scraper = cloudscraper.create_scraper(
        browser={"custom": "Mozilla/5.0"}  # emulate a real browser
    )
    api_key = "38e804c6-4cd5-4cb4-83bb-709aa16cf64c"

    tasks = []
    for route in app.routes:
        if not hasattr(route, "methods") or not route.path.startswith("/"):
            continue
        if route.path.startswith(("/docs", "/static", "/openapi.json")):
            continue  # skip docs/static

        path = fill_path(route.path)
        full_url = f"https://m.mm29942.com{path}"
        for m in (route.methods - {"HEAD", "OPTIONS"}):
            body = {} if m in {"POST", "PUT", "PATCH"} else None
            headers = {"X-API-Key": api_key}
            tasks.append(
                asyncio.create_task(
                    check_route(scraper, m, full_url, json_body=body)
                )
            )

    results = await asyncio.gather(*tasks)
    # report any failures
    for i, (route) in enumerate(app.routes):
        # correlate simply by index
        status, snippet = results[i]
        if isinstance(status, int) and 200 <= status < 400:
            continue
        print(f"[FAIL] {route.methods} {route.path} → {status}")

if __name__ == "__main__":
    asyncio.run(main())
