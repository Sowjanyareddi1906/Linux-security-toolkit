

import subprocess
import os
from datetime import datetime


# ============================================================
# LINUX SECURITY & SYSTEM ENUMERATION TOOLKIT
# ============================================================


def run_command(command):
    """
    Execute a Linux command and return its output.
    """

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            return result.stdout.strip()

        return result.stderr.strip()

    except Exception as error:
        return f"Error: {error}"


# ============================================================
# SYSTEM INFORMATION
# ============================================================

def collect_system_information():

    username = run_command(["whoami"])
    user_id = run_command(["id"])
    hostname = run_command(["hostname"])
    kernel = run_command(["uname", "-a"])

    os_info = run_command(["cat", "/etc/os-release"])

    return {
        "username": username,
        "user_id": user_id,
        "hostname": hostname,
        "kernel": kernel,
        "os_info": os_info
    }


# ============================================================
# NETWORK INFORMATION
# ============================================================

def collect_network_information():

    network_interfaces = run_command(["ip", "addr"])
    routing_table = run_command(["ip", "route"])
    listening_services = run_command(["ss", "-tuln"])

    return {
        "network_interfaces": network_interfaces,
        "routing_table": routing_table,
        "listening_services": listening_services
    }


# ============================================================
# SECURITY OBSERVATIONS
# ============================================================

def generate_security_observations(network_data):

    observations = []

    interfaces = network_data["network_interfaces"]
    services = network_data["listening_services"]

    if "127.0.0.1" in interfaces:
        observations.append(
            "Loopback interface detected (127.0.0.1)."
        )

    if "LISTEN" in services:
        observations.append(
            "One or more listening network services were detected."
        )

    if "default" in network_data["routing_table"]:
        observations.append(
            "A default network route is configured."
        )

    if not observations:
        observations.append(
            "No basic security observations were generated."
        )

    return observations


# ============================================================
# TEXT REPORT
# ============================================================

def create_text_report(system_data, network_data, observations):

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""
============================================================
LINUX SECURITY & SYSTEM ENUMERATION REPORT
============================================================

Generated: {current_time}


SYSTEM INFORMATION
------------------------------------------------------------

Current User:
{system_data["username"]}

User / Group Information:
{system_data["user_id"]}

Hostname:
{system_data["hostname"]}

Kernel:
{system_data["kernel"]}


OS INFORMATION
------------------------------------------------------------

{system_data["os_info"]}


NETWORK INTERFACES
------------------------------------------------------------

{network_data["network_interfaces"]}


ROUTING TABLE
------------------------------------------------------------

{network_data["routing_table"]}


LISTENING SERVICES
------------------------------------------------------------

{network_data["listening_services"]}


SECURITY OBSERVATIONS
------------------------------------------------------------

"""

    for observation in observations:
        report += f"- {observation}\n"

    report += """
============================================================
END OF REPORT
============================================================
"""

    return report


# ============================================================
# HTML REPORT
# ============================================================

def create_html_report(system_data, network_data, observations):

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    observations_html = ""

    for observation in observations:
        observations_html += f"<li>{observation}</li>"

    html = f"""
<!DOCTYPE html>
<html>
<head>

<title>Linux Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background-color: #f4f4f4;
}}

.container {{
    background-color: white;
    padding: 30px;
    border-radius: 10px;
}}

h1 {{
    color: #222;
}}

h2 {{
    color: #444;
    border-bottom: 1px solid #ccc;
    padding-bottom: 5px;
}}

pre {{
    background-color: #eeeeee;
    padding: 15px;
    overflow-x: auto;
    border-radius: 5px;
}}

li {{
    margin: 8px 0;
}}

</style>

</head>

<body>

<div class="container">

<h1>Linux Security & System Enumeration Report</h1>

<p><b>Generated:</b> {current_time}</p>

<h2>System Information</h2>

<pre>
User:
{system_data["username"]}

User / Group:
{system_data["user_id"]}

Hostname:
{system_data["hostname"]}

Kernel:
{system_data["kernel"]}
</pre>

<h2>Operating System</h2>

<pre>{system_data["os_info"]}</pre>

<h2>Network Interfaces</h2>

<pre>{network_data["network_interfaces"]}</pre>

<h2>Routing Table</h2>

<pre>{network_data["routing_table"]}</pre>

<h2>Listening Services</h2>

<pre>{network_data["listening_services"]}</pre>

<h2>Security Observations</h2>

<ul>
{observations_html}
</ul>

</div>

</body>
</html>
"""

    return html


# ============================================================
# FULL ENUMERATION
# ============================================================

def run_full_scan():

    print()
    print("=" * 60)
    print("STARTING SYSTEM ENUMERATION")
    print("=" * 60)

    print("\n[1/4] Collecting system information...")

    system_data = collect_system_information()

    print("[+] System information collected")

    print("\n[2/4] Collecting network information...")

    network_data = collect_network_information()

    print("[+] Network information collected")

    print("\n[3/4] Generating security observations...")

    observations = generate_security_observations(network_data)

    print("[+] Security observations generated")

    print("\n[4/4] Creating reports...")

    text_report = create_text_report(
        system_data,
        network_data,
        observations
    )

    html_report = create_html_report(
        system_data,
        network_data,
        observations
    )

    # Create reports directory if it does not exist
    os.makedirs("reports", exist_ok=True)

    # Save text report
    with open(
        "reports/system_report.txt",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(text_report)

    # Save HTML report
    with open(
        "reports/system_report.html",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html_report)

    print("[+] Text report saved")
    print("[+] HTML report saved")

    print()
    print("=" * 60)
    print("ENUMERATION COMPLETED SUCCESSFULLY")
    print("=" * 60)

    print("\nReports created:")
    print("1. reports/system_report.txt")
    print("2. reports/system_report.html")

    print("\nSecurity Observations:")

    for observation in observations:
        print(f"  - {observation}")

    print()


# ============================================================
# MAIN MENU
# ============================================================

def main():

    while True:

        print()
        print("=" * 60)
        print("       LINUX SECURITY & SYSTEM ENUMERATION TOOLKIT")
        print("=" * 60)

        print()
        print("1. Run Full Enumeration")
        print("2. Exit")

        print()

        choice = input("Enter your choice: ").strip()

        if choice == "1":

            run_full_scan()

            input("\nPress ENTER to return to the main menu...")

        elif choice == "2":

            print("\nExiting toolkit...")
            break

        else:

            print("\nInvalid choice. Please enter 1 or 2.")


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":
    main()