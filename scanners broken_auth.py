import asyncio
import aiohttp

REMEDIATION = (
    "Implement strong authentication mechanisms such as OAuth2 or JWT. "
    "Enforce multi-factor authentication and session management."
)

# Example payloads: try accessing protected endpoint without auth or with invalid tokens
BROKEN_AUTH_TESTS = [
    {"headers": {}},  # No auth header
    {"headers": {"Authorization": "Bearer invalidtoken"}},  # Invalid token
]


async def scan(endpoint):
    vulns = []
    async with aiohttp.ClientSession() as session:
        tasks = []
        for test in BROKEN_AUTH_TESTS:
            tasks.append(fetch(session, endpoint, test["headers"]))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # If endpoint returns 200 or 2xx without valid auth, broken auth likely
        for resp in responses:
            try:
                if resp["status"] and 200 <= resp["status"] < 300:
                    vulns.append(
                        {
                            "details": f"Endpoint {endpoint} allows access without proper authentication.",
                            "remediation": REMEDIATION,
                        }
                    )
                    break
            except Exception:
                continue

    return vulns


async def fetch(session, url, headers):
    try:
        async with session.get(url, headers=headers, timeout=10) as resp:
            text = await resp.text()
            return {"status": resp.status, "body": text}
    except Exception as e:
        return {"status": None, "body": str(e)}