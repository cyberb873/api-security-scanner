import json
import os

import jinja2


def load_endpoints(file_path):
    with open(file_path, "r") as f:
        lines = f.readlines()
    endpoints = [line.strip() for line in lines if line.strip()]
    return endpoints


def generate_reports(results, json_path, html_path):
    # Save JSON report
    with open(json_path, "w") as f:
        json.dump(results, f, indent=4)

    # Generate HTML report using Jinja2 template
    template_str = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>API Security Scanner Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #2c3e50; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; }
            th { background-color: #2980b9; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .vuln { color: #c0392b; font-weight: bold; }
            .remediation { color: #27ae60; }
        </style>
    </head>
    <body>
        <h1>API Security Scanner Report</h1>
        <p>Total vulnerabilities found: {{ results|length }}</p>
        {% if results %}
        <table>
            <thead>
                <tr>
                    <th>Vulnerability</th>
                    <th>Endpoint</th>
                    <th>Details</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {% for item in results %}
                <tr>
                    <td class="vuln">{{ item.vulnerability }}</td>
                    <td><a href="{{ item.endpoint }}" target="_blank">{{ item.endpoint }}</a></td>
                    <td>{{ item.details }}</td>
                    <td class="remediation">{{ item.remediation }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No vulnerabilities detected.</p>
        {% endif %}
    </body>
    </html>
    """

    template = jinja2.Template(template_str)
    html_content = template.render(results=results)

    with open(html_path, "w") as f:
        f.write(html_content)