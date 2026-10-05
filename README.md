Linux Security & System Enumeration Toolkit

A Python-based Linux security toolkit that collects basic system and network information, performs local security observations, and generates readable security reports.

Features

- Collects basic Linux system information
- Displays current user and user/group information
- Detects hostname and kernel information
- Collects operating system information
- Enumerates network interfaces
- Displays the routing table
- Identifies listening network services
- Generates basic security observations
- Creates text-based security reports
- Generates HTML security reports
- Provides a simple command-line interface

Project Structure

Linux-security-toolkit/
│
├── src/
│   └── main.py
│
├── reports/
│   └── system_report.txt
│
├── screenshots/
│
├── tests/
│
├── docs/
│
└── README.md

Technologies Used

- Python 3
- Linux / Kali Linux
- Linux system commands
- Git & GitHub
- HTML for report generation

How It Works

User
  ↓
Run Toolkit
  ↓
System Information Collection
  ↓
Network Information Collection
  ↓
Security Observation
  ↓
Report Generation
  ↓
TXT / HTML Report

How to Run

Open a terminal inside the project directory:

cd Linux-security-toolkit

Run:

python3 src/main.py

Select:

1. Run Full Enumeration
2. Exit

The toolkit collects the available local system and network information and generates the corresponding report.

Security Purpose

This project is intended for defensive security learning and authorized local-system assessment. It helps demonstrate basic Linux enumeration concepts that are useful in cybersecurity, vulnerability assessment, and security operations.

Future Improvements

- Add Nmap-based network discovery
- Add configurable scan modules
- Improve security-risk classification
- Add JSON report generation
- Add automated tests
- Add a graphical interface
- Add configurable logging

Author

Developed as a cybersecurity learning project using Python and Linux.
