# IoT Firmware Security Scanner v1.0

## 🛡️ Project Overview
The **IoT Firmware Security Scanner** is a comprehensive automated tool designed to analyze IoT device firmware for security vulnerabilities, malware, and misconfigurations. It provides a web-based interface for uploading firmware images, performing deep extraction, and generating detailed security reports.

---

## 🏗️ Architecture
The project follows a modular, layered architecture:

1.  **Frontend (Presentation Layer):**
    *   Developed using **HTML/CSS (Bootstrap/Custom)** and **JavaScript**.
    *   Provides a clean Dashboard for scan management and a detailed Report viewer.
2.  **Backend (Application Layer):**
    *   Powered by **Flask (Python)**.
    *   Handles file uploads, session management, and coordinates the scanning lifecycle.
3.  **Scanner Engine (Analysis Layer):**
    *   **FirmwareExtractor:** Uses `binwalk` for recursive extraction of firmware images.
    *   **RouterScanner:** The core analysis logic that orchestrates various security checks.
    *   **YaraScanner:** Scans extracted files for malware using YARA rules.
    *   **CVELookup:** Matches detected components (Kernel, BusyBox) against a local CVE database.
    *   **SeverityScore:** Calculates an overall risk score based on findings.
4.  **Storage Layer:**
    *   `uploads/`: Temporary storage for uploaded firmware.
    *   `extracted/`: Temporary sandbox for extracted filesystems.
    *   `reports/`: Permanent storage for scan results in JSON format.

---

## 🔄 Workflow
1.  **Authentication:** User logs in via the web portal.
2.  **Upload:** User uploads a firmware binary (`.bin`, `.img`, etc.) and selects the device type (e.g., Router).
3.  **Extraction:**
    *   The system validates the file.
    *   `binwalk` is invoked to extract the filesystem (SquashFS, CramFS, etc.) into a temporary directory.
4.  **Deep Scanning:**
    *   **Environment Check:** Detects BusyBox and Linux Kernel versions.
    *   **Credential Audit:** Parses `/etc/passwd` and `/etc/shadow` for hardcoded accounts or weak passwords.
    *   **Service Detection:** Identifies active services like Telnet, SSH, and Web servers.
    *   **Malware Scan:** Runs YARA rules against all extracted files to find known botnets (e.g., Mirai).
    *   **Vulnerability Matching:** Cross-references versions with the CVE database.
    *   **Configuration Audit:** Checks WiFi configs, certificates, and insecure file permissions (777/666).
5.  **Reporting:**
    *   A severity score (LOW/MEDIUM/HIGH) is calculated.
    *   A JSON report is saved permanently.
    *   The user is redirected to a visual dashboard displaying all findings.
6.  **Cleanup:** Temporary extraction directories are wiped to maintain security and disk space.

---

## 📂 Directory Structure
```text
D:\IOT of router only\
├── app.py                  # Main Flask application entry point
├── scanner/                # Core scanning logic package
│   ├── __init__.py         # Package initialization
│   ├── extract.py          # Firmware extraction logic (Binwalk wrapper)
│   ├── router_scanner.py   # Master scanner for router firmware
│   ├── yara_scanner.py     # Malware detection using YARA rules
│   ├── cve_lookup.py       # Local CVE database matching
│   ├── severity.py         # Risk scoring algorithm
│   ├── cve_db.json         # Local database of known vulnerabilities
│   └── yara_rules/         # Directory containing malware signatures (.yar)
├── templates/              # HTML templates for the web interface
│   ├── login.html          # Authentication page
│   ├── dashboard.html      # Scan initiation and history
│   └── report.html         # Detailed vulnerability report view
├── reports/                # Stored JSON reports (UUID-based)
├── uploads/                # Temporary firmware upload storage
├── logs/                   # System and scan logs
├── venv/                   # Python virtual environment
├── flow.txt                # High-level logic flow documentation
├── structure.txt           # Project directory layout notes
├── run.txt                 # Quick-start execution commands
└── deploy.txt              # Deployment and production notes
```

---

## 📄 File-by-File Explanation

### Core Application
*   **`app.py`**: The "brain" of the web server. It defines routes for login, the dashboard, and the `/scan` endpoint. It handles file saving and coordinates the `Extractor` and `Scanner` classes.

### Scanner Module (`scanner/`)
*   **`extract.py`**: Utilizes the `binwalk` tool to automatically identify and extract filesystems from binary blobs. It handles the creation and cleanup of temporary workspaces.
*   **`router_scanner.py`**: Contains the `RouterScanner` class. It performs a battery of tests:
    *   `check_busybox()` & `check_kernel()`: Identification of core components.
    *   `check_credentials()`: Extracts users and detects backdoor accounts.
    *   `check_services()`: Finds risky open services.
    *   `detect_suspicious()`: Greps for keywords like "backdoor" or "hack".
*   **`yara_scanner.py`**: Integrates the YARA library to scan every file in the extracted firmware against signatures in `yara_rules/botnet.yar`.
*   **`cve_lookup.py`**: A utility to query `cve_db.json` for known vulnerabilities based on the software versions detected during the scan.
*   **`severity.py`**: Implements a weighted scoring model. For example, a YARA malware hit is weighted 30%, while an open Telnet port adds a flat risk penalty.

### Data & Rules
*   **`cve_db.json`**: A curated list of CVEs relevant to IoT devices (BusyBox, Linux Kernel, etc.).
*   **`yara_rules/botnet.yar`**: Contains cryptographic signatures for detecting malware like Mirai, Gafgyt, and other IoT threats.

---

## 🚀 Getting Started

### Prerequisites
*   Python 3.12+
*   Binwalk (`sudo apt install binwalk` or equivalent)
*   YARA library

### Installation
1.  **Clone the repository:**
    ```bash
    cd "IOT of router only"
    ```
2.  **Activate Virtual Environment:**
    ```bash
    source venv/bin/activate
    ```
3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

### Running the App
```bash
python app.py
```
Access the dashboard at `http://127.0.0.1:5000`

---

## 🔒 Security Note
This tool is intended for security research and firmware auditing purposes only. Ensure you have authorization before scanning third-party firmware.
