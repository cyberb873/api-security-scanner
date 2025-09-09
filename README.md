# API Security Scanner

Detect OWASP API Security Top 10 (2023) vulnerabilities in your API endpoints.

## Features

- Detects API1 to API10 vulnerabilities.
- Concurrent scanning with asyncio + aiohttp.
- CLI interface with URL or file input.
- Generates JSON + HTML reports with remediation advice.
- Modular and extensible scanner modules.

## Setup

1. Clone the repo:

```bash
git clone https://github.com/yourusername/api-security-scanner.git
cd api-security-scanner
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
Usage
Scan a single endpoint:

bash

Run
Copy code
python api_scanner.py -u https://targetapi.com/v1/users
Scan multiple endpoints from a file (endpoints.txt):
RunCopy code :python api_scanner.py -f endpoints.txt
Adjust concurrency (default 5):
Run Copy code :python api_scanner.py -f endpoints.txt -c 10
Reports
Reports are saved in the /reports directory as JSON and HTML files with timestamps.
async def scan(endpoint) -> list[dict]:
    # Return list of vulnerabilities found with 'details' and 'remediation'

