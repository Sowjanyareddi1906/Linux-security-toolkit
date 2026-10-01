# Linux Security & System Enumeration Toolkit

A Python-based Linux security toolkit that collects basic system and network information, generates security observations, and produces TXT and HTML reports.

## Features

* Collects basic Linux system information
* Collects network configuration and information
* Identifies basic security observations
* Detects loopback network interfaces
* Checks for listening network services
* Checks for a configured default network route
* Generates a TXT security report
* Generates an HTML security report
* Simple command-line interface

## Project Structure

```text
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
├── docs/
│
├── tests/
│
└── README.md
```

## Requirements

* Python 3
* Linux / Kali Linux
* Standard Python libraries

## How to Run

Clone the repository:

```bash
git clone https://github.com/Sowjanyareddi1906/linux-security-toolkit.git
cd linux-security-toolkit
```

Run the toolkit:

```bash
python3 src/main.py
```

Select:

```text
1. Run Full Enumeration
2. Exit
```

After running the enumeration, reports are generated inside the `reports/` directory.

## Output

The toolkit generates:

* `reports/system_report.txt`
* `reports/system_report.html`

The reports contain collected system and network information along with basic security observations.

## Security Observations

The toolkit can report observations such as:

* Loopback interface detected
* Listening network services detected
* Default network route configured

These observations are intended for basic local security assessment and learning purposes.

## Technologies Used

* Python
* Linux
* Kali Linux
* Git & GitHub

## Purpose

This project was developed as a cybersecurity learning project to practice Python programming, Linux system information gathering, network enumeration, report generation, and basic security analysis.

## Disclaimer

This toolkit is intended for educational and authorized security assessment purposes only. Use it only on systems that you own or have explicit permission to assess.
