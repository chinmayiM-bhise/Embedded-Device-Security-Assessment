# IoT Firmware Security Scanner

A FastAPI-based web application for scanning IoT firmware for vulnerabilities, secrets, malware, and hardening issues.

## Running the Project in WSL

Follow these instructions to set up and run the scanner in a Windows Subsystem for Linux (WSL) environment.

### 1. Prerequisites

Install the necessary system dependencies in your WSL distribution (e.g., Ubuntu):

```bash
sudo apt update
sudo apt install binwalk libmagic1 yara -y
```

### 2. Setup

1.  **Navigate to the project root:**
    ```bash
    cd "/mnt/d/minor project"
    ```

2.  **Activate the virtual environment:**
    ```bash
    source venv_wsl/bin/activate
    ```

3.  **Install Python dependencies (if not already installed):**
    ```bash
    pip install -r requirements.txt
    ```

## Project Progress (v1.1)

The scanner has been upgraded to a professional-grade security tool with the following enhancements:

- **Intelligent Vulnerability Scanning:** Integrated with the CIRCL CVE Search API for real-time threat intelligence.
- **Deep Malware Detection:** Added a multi-engine approach using YARA rules (Mirai, Gafgyt, Hajime), cryptographic hash matching, and location-aware heuristics.
- **Binary Hardening Analysis:** Automated detection of NX, PIE, and Stack Canary protections in ELF binaries.
- **Dangerous Function Detection:** Identifies risky C functions (e.g., `strcpy`, `system`) in compiled code.
- **Professional Dashboard:** A sleek, dark-themed "Control Center" UI with interactive charts and live progress tracking.
- **Enterprise Reporting:** Redesigned PDF reports with severity badges, executive summaries, and structured remediation advice.

### 3. Execution

You can interact with the scanner via the Web Dashboard or the Command Line.

#### Option A: Web Dashboard (Recommended)

1.  **Start the API server:**
    ```bash
    python3 -m iot_scanner.web.api
    ```
2.  **Access the Dashboard:**
    Open [http://localhost:8000](http://localhost:8000) in your browser.
3.  **Perform an Audit:**
    - Go to **"New Scan"**.
    - Upload your firmware binary (supports `.bin`, `.zip`, `.img`, etc.).
    - Watch the live **"Control Center"** as it unpacks and analyzes the target.
    - View results in the interactive charts and download the **Professional PDF Report**.

#### Option B: Enterprise CLI

For automated audits or headless environments, use the built-in CLI:

```bash
# Run a full security audit
python3 -m iot_scanner.cli.main scan firmware.zip -o my_results_dir
```

- **Results:** A JSON file (`results.json`) and a PDF report (`audit_report.pdf`) will be generated in your output directory.
- **Help:** Run `python3 -m iot_scanner.cli.main scan --help` for all options.

## Project Structure

- `iot_scanner/core/`: Core analysis logic (static analysis, vulnerability scanning, etc.).
- `iot_scanner/web/`: FastAPI application and static web assets.
- `uploads/`: Temporary storage for uploaded firmware.
- `results/`: Extracted firmware files and generated PDF reports.
- `iot_scanner.db`: SQLite database for scan history.
