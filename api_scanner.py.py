import asyncio
import json
import os
import sys
from datetime import datetime

import click

from scanners import (
    bola,
    broken_auth,
    property_auth,
    resource_consumption,
    function_auth,
    sensitive_flows,
    ssrf,
    misconfiguration,
    inventory,
    unsafe_consumption,
)
from utils import generate_reports, load_endpoints

SCANNERS = [
    ("API1: Broken Object Level Authorization (BOLA)", bola.scan),
    ("API2: Broken Authentication", broken_auth.scan),
    ("API3: Broken Object Property Level Authorization", property_auth.scan),
    ("API4: Unrestricted Resource Consumption", resource_consumption.scan),
    ("API5: Broken Function Level Authorization", function_auth.scan),
    ("API6: Unrestricted Access to Sensitive Business Flows", sensitive_flows.scan),
    ("API7: Server Side Request Forgery (SSRF)", ssrf.scan),
    ("API8: Security Misconfiguration", misconfiguration.scan),
    ("API9: Improper Inventory Management", inventory.scan),
    ("API10: Unsafe Consumption of APIs", unsafe_consumption.scan),
]

REPORTS_DIR = "reports"


@click.command()
@click.option("-u", "--url", "urls", multiple=True, help="Target API endpoint URL(s).")
@click.option("-f", "--file", "file_path", type=click.Path(exists=True), help="File with list of API endpoints (one per line).")
@click.option("-c", "--concurrency", default=5, help="Number of concurrent requests (default: 5).")
def main(urls, file_path, concurrency):
    """
    API Security Scanner - Detect OWASP API Security Top 10 (2023) vulnerabilities.
    """
    if not urls and not file_path:
        click.echo("Error: Provide at least one URL (-u) or a file with URLs (-f).", err=True)
        sys.exit(1)

    endpoints = set(urls)
    if file_path:
        endpoints.update(load_endpoints(file_path))

    if not endpoints:
        click.echo("No valid endpoints to scan.", err=True)
        sys.exit(1)

    click.echo(f"Starting scan on {len(endpoints)} endpoint(s) with concurrency={concurrency}...\n")

    # Run all scanners concurrently on all endpoints
    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(run_scanners(endpoints, concurrency))

    # Prepare reports directory
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_report_path = os.path.join(REPORTS_DIR, f"api_scan_report_{timestamp}.json")
    html_report_path = os.path.join(REPORTS_DIR, f"api_scan_report_{timestamp}.html")

    generate_reports(results, json_report_path, html_report_path)

    click.echo(f"\nScan complete. Reports saved to:\n- {json_report_path}\n- {html_report_path}")


async def run_scanners(endpoints, concurrency):
    """
    Run all vulnerability scanners concurrently on all endpoints.
    """
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def scan_endpoint(scanner_name, scan_func, endpoint):
        async with semaphore:
            try:
                vulns = await scan_func(endpoint)
                if vulns:
                    for v in vulns:
                        results.append(
                            {
                                "vulnerability": scanner_name,
                                "endpoint": endpoint,
                                "details": v["details"],
                                "remediation": v["remediation"],
                            }
                        )
            except Exception as e:
                results.append(
                    {
                        "vulnerability": scanner_name,
                        "endpoint": endpoint,
                        "details": f"Error during scan: {e}",
                        "remediation": "N/A",
                    }
                )

    tasks = []
    for endpoint in endpoints:
        for scanner_name, scan_func in SCANNERS:
            tasks.append(scan_endpoint(scanner_name, scan_func, endpoint))

    await asyncio.gather(*tasks)
    return results


if __name__ == "__main__":
    main()