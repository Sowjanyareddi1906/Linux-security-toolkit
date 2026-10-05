import os
import platform
import socket
import subprocess
from datetime import datetime
from html import escape
from urllib.parse import urlparse


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")

TEXT_REPORT = os.path.join(REPORTS_DIR, "security_report.txt")
HTML_REPORT = os.path.join(REPORTS_DIR, "security_report.html")


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def run_command(command, timeout=10):
    """
    Execute a Linux command safely and return its output.
    """

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = result.stdout.strip()

        if not output:
            output = result.stderr.strip()

        return output if output else "No information available."

    except subprocess.TimeoutExpired:
        return "Command timed out."

    except Exception as error:
        return f"Command failed: {error}"


def normalize_target(target):
    """
    Remove protocol/path information and return a hostname/IP.
    """

    target = target.strip()

    if not target:
        return ""

    if "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname or ""

    else:
        target = target.split("/")[0]

    return target.strip()


def resolve_target(target):
    """
    Resolve a hostname or IP address.
    """

    try:
        address = socket.gethostbyname(target)
        return address

    except socket.gaierror:
        return None


def is_local_target(target, resolved_ip):
    """
    Determine whether the target refers to the current machine.
    """

    local_names = {
        "localhost",
        socket.gethostname(),
        socket.getfqdn()
    }

    if target.lower() in local_names:
        return True

    if resolved_ip in {
        "127.0.0.1",
        "::1"
    }:
        return True

    return False


# ============================================================
# LOCAL SYSTEM ENUMERATION
# ============================================================

def collect_system_information():
    """
    Collect basic information from the current Linux system.
    """

    return {
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "distribution": run_command(
            ["bash", "-c", "grep '^PRETTY_NAME=' /etc/os-release"]
        ),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "Not available",
        "uptime": run_command(["uptime", "-p"]),
        "current_user": os.getenv("USER", "Unknown"),
        "date_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def collect_network_information():
    """
    Collect network information from the current Linux system.
    """

    return {
        "ip_addresses": run_command(
            ["ip", "-brief", "address"]
        ),

        "routing_table": run_command(
            ["ip", "route"]
        ),

        "listening_services": run_command(
            ["ss", "-tuln"]
        )
    }


# ============================================================
# TARGET ANALYSIS
# ============================================================

def test_target_reachability(target):
    """
    Check whether the target responds to a single ping request.
    """

    result = run_command(
        ["ping", "-c", "1", "-W", "2", target],
        timeout=5
    )

    if "1 received" in result or "bytes from" in result:
        return "Reachable"

    return "No response"


def check_common_ports(target):
    """
    Perform a basic TCP connection check against common services.

    This is intended only for systems the user owns or is
    explicitly authorized to assess.
    """

    common_ports = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        25: "SMTP",
        53: "DNS",
        3306: "MySQL",
        5432: "PostgreSQL"
    }

    results = []

    for port, service in common_ports.items():

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.5)

        try:
            connection = sock.connect_ex(
                (target, port)
            )

            if connection == 0:
                results.append(
                    f"{port}/tcp - OPEN - {service}"
                )

        except Exception:
            pass

        finally:
            sock.close()

    if not results:
        return "No common TCP ports detected as open."

    return "\n".join(results)


# ============================================================
# SECURITY ANALYSIS
# ============================================================

def generate_security_observations(
    target,
    resolved_ip,
    reachability,
    port_results,
    network_data=None
):
    """
    Generate basic security observations.
    """

    observations = []

    if reachability == "Reachable":
        observations.append(
            "Target responded to the reachability check."
        )
    else:
        observations.append(
            "Target did not respond to the reachability check."
        )

    if "No common TCP ports" not in port_results:
        observations.append(
            "One or more common TCP services were detected as open."
        )
    else:
        observations.append(
            "No tested common TCP services were detected as open."
        )

    if network_data:

        ip_data = network_data["ip_addresses"]
        listening_data = network_data["listening_services"]
        route_data = network_data["routing_table"]

        if "127.0.0.1" in ip_data:
            observations.append(
                "Loopback interface detected on the local system."
            )

        if listening_data and "No information available" not in listening_data:
            observations.append(
                "One or more local listening network services were detected."
            )

        if route_data and "default" in route_data:
            observations.append(
                "A default network route is configured on the local system."
            )

    return observations


def assign_risk_level(port_results, reachability):
    """
    Assign a simple informational risk level.

    This is NOT a vulnerability scanner.
    """

    if "No common TCP ports" not in port_results:
        return "MEDIUM"

    if reachability == "Reachable":
        return "LOW"

    return "INFO"


# ============================================================
# REPORT GENERATION
# ============================================================

def create_text_report(
    target,
    resolved_ip,
    reachability,
    port_results,
    risk_level,
    system_data,
    network_data,
    observations
):
    """
    Create a readable TXT security report.
    """

    lines = []

    lines.append("=" * 70)
    lines.append("LINUX SECURITY & SYSTEM ENUMERATION TOOLKIT")
    lines.append("=" * 70)

    lines.append("")
    lines.append("TARGET INFORMATION")
    lines.append("-" * 70)
    lines.append(f"Target: {target}")
    lines.append(f"Resolved IP: {resolved_ip}")
    lines.append(f"Reachability: {reachability}")
    lines.append(f"Risk Level: {risk_level}")

    lines.append("")
    lines.append("COMMON TCP SERVICES")
    lines.append("-" * 70)
    lines.append(port_results)

    if system_data:

        lines.append("")
        lines.append("LOCAL SYSTEM INFORMATION")
        lines.append("-" * 70)

        for key, value in system_data.items():
            lines.append(
                f"{key.replace('_', ' ').title()}: {value}"
            )

        lines.append("")
        lines.append("LOCAL NETWORK INFORMATION")
        lines.append("-" * 70)

        lines.append("")
        lines.append("IP ADDRESSES")
        lines.append(network_data["ip_addresses"])

        lines.append("")
        lines.append("ROUTING TABLE")
        lines.append(network_data["routing_table"])

        lines.append("")
        lines.append("LOCAL LISTENING SERVICES")
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


def create_html_report(
    target,
    resolved_ip,
    reachability,
    port_results,
    risk_level,
    system_data,
    network_data,
    observations
):
    """
    Create a readable HTML security report.
    """

    system_rows = ""

    if system_data:

        for key, value in system_data.items():

            system_rows += (
                "<tr>"
                f"<td>{escape(key.replace('_', ' ').title())}</td>"
                f"<td>{escape(str(value))}</td>"
                "</tr>"
            )

    observation_items = ""

    for observation in observations:
        observation_items += (
            f"<li>{escape(observation)}</li>"
        )

    html = f"""<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<title>
Linux Security Toolkit Report
</title>

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

<h1>
Linux Security & System Enumeration Toolkit
</h1>

<p>
Security assessment report for an authorized target.
</p>

<h2>Target Information</h2>

<table>

<tr>
<th>Property</th>
<th>Value</th>
</tr>

<tr>
<td>Target</td>
<td>{escape(target)}</td>
</tr>

<tr>
<td>Resolved IP</td>
<td>{escape(str(resolved_ip))}</td>
</tr>

<tr>
<td>Reachability</td>
<td>{escape(reachability)}</td>
</tr>

<tr>
<td>Risk Level</td>
<td>{escape(risk_level)}</td>
</tr>

</table>

<h2>Common TCP Services</h2>

<pre>{escape(port_results)}</pre>

"""

    if system_data:

        html += f"""

<h2>Local System Information</h2>

<table>

<tr>
<th>Property</th>
<th>Value</th>
</tr>

{system_rows}

</table>

<h2>Local IP Addresses</h2>

<pre>
{escape(network_data["ip_addresses"])}
</pre>

<h2>Local Routing Table</h2>

<pre>
{escape(network_data["routing_table"])}
</pre>

<h2>Local Listening Services</h2>

<pre>
{escape(network_data["listening_services"])}
</pre>

"""

    html += f"""

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


# ============================================================
# MAIN ENUMERATION WORKFLOW
# ============================================================

def run_full_scan():

    os.makedirs(REPORTS_DIR, exist_ok=True)

    print()
    print("=" * 65)
    print("       LINUX SECURITY & SYSTEM ENUMERATION TOOLKIT")
    print("=" * 65)

    print()
    print(
        "Use this tool only on systems you own or are authorized to assess."
    )

    print()

    target = input(
        "Enter target IP address or hostname: "
    ).strip()

    target = normalize_target(target)

    if not target:

        print("\n[!] Target cannot be empty.")
        return

    resolved_ip = resolve_target(target)

    if not resolved_ip:

        print(
            "\n[!] Unable to resolve the target."
        )

        return

    print(
        f"\n[+] Target resolved to: {resolved_ip}"
    )

    print("\n[1/5] Checking target reachability...")

    reachability = test_target_reachability(
        resolved_ip
    )

    print(
        f"[+] Reachability: {reachability}"
    )

    print("\n[2/5] Checking common TCP services...")

    port_results = check_common_ports(
        resolved_ip
    )

    print("[+] Service check completed")

    system_data = None
    network_data = None

    if is_local_target(
        target,
        resolved_ip
    ):

        print(
            "\n[3/5] Collecting local system information..."
        )

        system_data = collect_system_information()

        print(
            "[+] Local system information collected"
        )

        print(
            "\n[4/5] Collecting local network information..."
        )

        network_data = collect_network_information()

        print(
            "[+] Local network information collected"
        )

    else:

        print(
            "\n[3/5] Target is remote."
        )

        print(
            "[+] Local system collection skipped."
        )

        print(
            "\n[4/5] Preparing target security observations..."
        )

    print(
        "\n[5/5] Generating security analysis..."
    )

    observations = generate_security_observations(
        target,
        resolved_ip,
        reachability,
        port_results,
        network_data
    )

    risk_level = assign_risk_level(
        port_results,
        reachability
    )

    print(
        f"[+] Risk level: {risk_level}"
    )

    create_text_report(
        target,
        resolved_ip,
        reachability,
        port_results,
        risk_level,
        system_data,
        network_data,
        observations
    )

    create_html_report(
        target,
        resolved_ip,
        reachability,
        port_results,
        risk_level,
        system_data,
        network_data,
        observations
    )

    print()
    print("=" * 65)
    print("       ENUMERATION COMPLETED SUCCESSFULLY")
    print("=" * 65)

    print("\nReports created:")
    print("1. reports/security_report.txt")
    print("2. reports/security_report.html")

    print("\nSecurity observations:")

    for observation in observations:

        print(
            f" - {observation}"
        )

    print()


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    run_full_scan()