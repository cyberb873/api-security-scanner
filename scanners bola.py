import asyncio
import json
from urllib.parse import urljoin

import aiohttp

# Example payloads to test BOLA
# This is a simplified example: tries to access other users' objects by changing IDs
BOLA_PAYLOADS = [
    {"id": "1"},  # Normal user id
    {"id": "2"},  # Another user id to test unauthorized access
    {"id": "9999"},  # Non-existent id
]

REMEDIATION = (
    "Implement strict object-level authorization checks on the server side. "
    "Verify that the authenticated user has permission to access the requested object."
)


async def scan(endpoint):
    """
    Scan for Broken Object Level Authorization (BOLA).
    This example assumes the endpoint accepts GET requests with query param 'id'.
    """
    vulns = []
    async with aiohttp.ClientSession() as session:
        tasks = []
        for payload in BOLA_PAYLOADS:
            url = endpoint
            params = payload
            tasks.append(fetch(session, url, params))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Basic heuristic: if response for id=2 returns 200 and id=1 is normal user,
        # then BOLA might exist.
        # This is a simplified example; real checks would be more complex.
        try:
            resp_1 = responses[0]
            resp_2 = responses[1]
            if (
                resp_1["status"] == 200
                and resp_2["status"] == 200
                and resp_1["body"] != resp_2["body"]
            ):
                vulns.append(
                    {
                        "details": f"Endpoint {endpoint} allows access to objects of other users (id=2).",
                        "remediation": REMEDIATION,
                    }
                )
        except Exception:
            pass

    return vulns


async def fetch(session, url, params):
    try:
        async with session.get(url, params=params, timeout=10) as resp:
            text = await resp.text()
            return {"status": resp.status, "body": text}
    except Exception as e:
        return {"status": None, "body": str(e)}