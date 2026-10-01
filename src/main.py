
import os
import platform
import socket
import subprocess
from datetime import datetime
from html import escape


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")

TEXT_REPORT = os.path.join(REPORTS_DIR, "system_report.txt")
HTML_REPORT = os.path.join(REPORTS_DIR, "system_report.html")


def run_command(command):
    """Run a Linux command and safely return its output."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout.strip()

        if not output:
            output = result.stderr.strip()

        return output if output else "No information available."

    except Exception as error:
        return f"Unable to execute command: {error}"


def collect_system_information():
    """Collect basic local system information."""

    return {
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "distribution": run_command(["bash", "-c", "cat /etc/os-release | grep PRETTY_NAME"]),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "Not available",
        "uptime": run_command(["uptime", "-p"]),
        "current_user": os.getenv("USER", "Unknown"),
        "date_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def collect_network_information():
    """Collect basic local network information."""

    return {
        "ip_addresses": run_command(["ip", "-brief", "address"]),
        "routing_table": run_command(["ip", "route"]),
        "listening_services": run_command(["ss", "-tuln"])
    }


def generate_security_observations(network_data):
    """Generate simple security observations from local network data."""

    observations = []

    ip_data = network_data["ip_addresses"]
    listening_data = network_data["listening_services"]
    route_data = network_data["routing_table"]

    if "127.0.0.1" in ip_data:
        observations.append(
            "Loopback interface detected (127.0.0.1)."
        )

    if listening_data and "No information available" not in listening_data:
        observations.append(
            "One or more listening network services were detected."
        )

    if route_data and "default" in route_data:
        observations.append(
            "A default network route is configured."
        )

    if not observations:
        observations.append(
            "No basic security observations were generated."
        )

    return observations


def create_text_report(system_data, network_data, observations):
    """Create a human-readable text report."""

    lines = []

    lines.append("=" * 70)
    lines.append("LINUX SECURITY & SYSTEM ENUMERATION TOOLKIT")
    lines.append("=" * 70)
    lines.append("")
    lines.append("SYSTEM INFORMATION")
    lines.append("-" * 70)

    for key, value in system_data.items():
        lines.append(f"{key.replace('_', ' ').title()}: {value}")

    lines.append("")
    lines.append("NETWORK INFORMATION")
    lines.append("-" * 70)

    lines.append("")
    lines.append("IP ADDRESSES")
    lines.append(network_data["ip_addresses"])

    lines.append("")
    lines.append("ROUTING TABLE")
    lines.append(network_data["routing_table"])

    lines.append("")
    lines.append("LISTENING SERVICES")
    lines.append(network_data["listening_services"])

    lines.append("")
    lines.append("SECURITY OBSERVATIONS")
    lines.append("-" * 70)

    for observation in observations:
        lines.append(f"- {observation}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    with open(TEXT_REPORT, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))


def create_html_report(system_data, network_data, observations):
    """Create an HTML version of the report."""

    system_rows = ""

    for key, value in system_data.items():
        system_rows += (
            f"<tr>"
            f"<td>{escape(key.replace('_', ' ').title())}</td>"
            f"<td>{escape(str(value))}</td>"
            f"</tr>"
        )

    observation_items = ""

    for observation in observations:
        observation_items += f"<li>{escape(observation)}</li>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Linux Security Toolkit Report</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f4f4f4;
            color: #222;
        }}

        .container {{
            max-width: 1000px;
            margin: auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
        }}

        h1 {{
            margin-bottom: 5px;
        }}

        h2 {{
            margin-top: 30px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            border: 1px solid #ccc;
            padding: 10px;
            text-align: left;
        }}

        th {{
            background: #eee;
        }}

        pre {{
            background: #111;
            color: #eee;
            padding: 15px;
            overflow-x: auto;
            border-radius: 6px;
        }}

        li {{
            margin: 8px 0;
        }}
    </style>
</head>

<body>

<div class="container">

    <h1>Linux Security & System Enumeration Toolkit</h1>

    <p>
        Local system and network enumeration report.
    </p>

    <p>
        Generated on: {escape(system_data["date_time"])}
    </p>

    <h2>System Information</h2>

    <table>
        <tr>
            <th>Property</th>
            <th>Value</th>
        </tr>

        {system_rows}
    </table>

    <h2>IP Addresses</h2>

    <pre>{escape(network_data["ip_addresses"])}</pre>

    <h2>Routing Table</h2>

    <pre>{escape(network_data["routing_table"])}</pre>

    <h2>Listening Network Services</h2>

    <pre>{escape(network_data["listening_services"])}</pre>

    <h2>Security Observations</h2>

    <ul>
        {observation_items}
    </ul>

</div>

</body>
</html>
"""

    with open(HTML_REPORT, "w", encoding="utf-8") as file:
        file.write(html)


def run_full_scan():
    """Run the complete local enumeration process."""

    os.makedirs(REPORTS_DIR, exist_ok=True)

    print()
    print("=" * 60)
    print("LINUX SECURITY & SYSTEM ENUMERATION TOOLKIT")
    print("=" * 60)

    print("\n[+] Starting system enumeration...")

    system_data = collect_system_information()
    print("[+] System information collected")

    network_data = collect_network_information()
    print("[+] Network information collected")

    observations = generate_security_observations(network_data)
    print("[+] Security observations generated")

    create_text_report(
        system_data,
        network_data,
        observations
    )

    create_html_report(
        system_data,
        network_data,
        observations
    )

    print("[+] Reports generated")

    print("\n" + "=" * 60)
    print("ENUMERATION COMPLETED SUCCESSFULLY")
    print("=" * 60)

    print("\nReports created:")
    print("1. reports/system_report.txt")
    print("2. reports/system_report.html")

    print("\nSecurity observations:")

    for observation in observations:
        print(f" - {observation}")

    print()


if __name__ == "__main__":
    run_full_scan()