Linux Security & System Enumeration Toolkit

A Python-based cybersecurity toolkit for performing basic Linux system and network enumeration on an authorized local system.

The project collects useful system and network information, performs simple security observations, and generates readable TXT and HTML reports.

Features

- Collects Linux system information
- Detects hostname, operating system, kernel and architecture
- Identifies the current user and system uptime
- Enumerates network interfaces and IP addresses
- Displays the local routing table
- Identifies listening TCP/UDP services
- Performs basic security observations
- Accepts a target IP address or hostname
- Handles invalid target input
- Generates structured TXT reports
- Generates browser-friendly HTML reports
- Designed for authorized security assessment and learning

How It Works

User Input
    ↓
Target Validation
    ↓
Target Resolution
    ↓
Basic Network Enumeration
    ↓
Local System Information
    ↓
Security Observations
    ↓
Report Generation
    ↓
TXT + HTML Reports

Project Structure

Linux-security-toolkit/
│
├── src/
│   └── main.py
│
├── reports/
│   ├── system_report.txt
│   └── system_report.html
│
├── screenshots/
│
├── tests/
│
├── docs/
│
├── .gitignore
│
└── README.md

Technologies Used

- Python 3
- Linux / Kali Linux
- Linux networking commands
- HTML & CSS
- Git
- GitHub

Requirements

- Python 3.x
- Linux-based environment
- Basic Linux networking utilities

The toolkit is designed and tested in Kali Linux.

How to Run

Clone the repository and move into the project directory:

cd Linux-security-toolkit

Run the toolkit:

python3 src/main.py

The program will request a target IP address or hostname.

Example:

Enter target IP address or hostname: localhost

The toolkit then performs the available enumeration and generates the corresponding reports.

Generated Reports

The toolkit produces two report formats:

TXT Report

A simple terminal-friendly report containing:

- System information
- Network information
- Routing information
- Listening services
- Security observations

HTML Report

A browser-friendly version of the assessment report with structured tables and sections for easier analysis.

The generated reports are stored inside:

reports/

Example Security Observations

Depending on the system being assessed, the toolkit can identify observations such as:

- Loopback interface availability
- Listening network services
- Default network route configuration

These observations are intended as basic indicators for security learning and are not a replacement for a complete vulnerability assessment.

Testing

The toolkit was tested with:

- Localhost input
- IP-based input
- Hostname-based input
- Invalid target input
- TXT report generation
- HTML report generation

Security & Ethical Use

This project is intended for educational purposes and authorized security assessment only.

Only use the toolkit against systems, devices, and networks that you own or have explicit permission to assess.

Future Improvements

Planned improvements include:

- Nmap-based service discovery
- More detailed port and service analysis
- Improved security-risk classification
- JSON report generation
- Automated unit tests
- Configurable scan modules
- Improved logging
- Additional Linux security checks

Author

Developed as a cybersecurity learning project using Python and Linux, with a focus on understanding practical system enumeration and security assessment concepts.