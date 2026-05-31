import pytest
import os
import shutil
from iot_scanner.core.secret_scanner import SecretScanner
from iot_scanner.core.static_analyzer import StaticAnalyzer
from iot_scanner.core.vulnerability_scanner import VulnerabilityScanner
from create_mock_firmware import create_mock_firmware

TEST_DIR = "test_run_data"

@pytest.fixture(scope="module", autouse=True)
def setup_test_data():
    """Setup mock firmware once for all tests in this module."""
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)
    create_mock_firmware(TEST_DIR)
    yield
    # Cleanup after all tests
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)

def test_secret_scanner():
    """Test that secrets are correctly identified."""
    scanner = SecretScanner(TEST_DIR)
    findings = scanner.scan_directory()
    
    # Check for specific secrets created in create_mock_firmware
    found_types = [f["type"] for f in findings]
    assert "Google API Key" in found_types
    assert "Generic Password/Token" in found_types
    assert "SSH Private Key" in found_types

def test_static_analyzer():
    """Test that sensitive files are identified."""
    analyzer = StaticAnalyzer(TEST_DIR)
    findings = analyzer.run_analysis()
    
    # Check for /etc/shadow and /etc/passwd
    found_files = [f["file"] for f in findings if f["type"] == "Sensitive File"]
    assert "/etc/shadow" in found_files
    assert "/etc/passwd" in found_files

def test_static_analyzer_dangerous_functions():
    """Test that dangerous functions in binaries are detected."""
    analyzer = StaticAnalyzer(TEST_DIR)
    findings = analyzer.run_analysis()
    
    # Check for dangerous functions in bin/vulnerable_app
    vulnerable_findings = [f for f in findings if f["type"] == "Dangerous Function" and "vulnerable_app" in f["file"]]
    assert len(vulnerable_findings) > 0
    description = vulnerable_findings[0]["description"]
    assert "strcpy" in description
    assert "system" in description

def test_malware_scanner():
    """Test that malware indicators are detected."""
    from iot_scanner.core.malware_scanner import MalwareScanner
    scanner = MalwareScanner(TEST_DIR)
    findings = scanner.run_scan()
    
    # Check for heuristic detection of tmp/bot.sh
    heuristic_findings = [f for f in findings if f["type"] == "Heuristic"]
    assert len(heuristic_findings) > 0
    assert any("bot.sh" in f["file"] for f in heuristic_findings)



def test_vulnerability_scanner():
    """Test that software components and CVEs are identified."""
    scanner = VulnerabilityScanner(TEST_DIR)
    results = scanner.run_scan()
    
    # Check components
    found_components = [c["name"] for c in results["components"]]
    assert "BusyBox" in found_components
    assert "OpenSSL" in found_components
    
    # Check vulnerabilities (based on our mock CVE database)
    vulnerabilities = results["vulnerabilities"]
    assert len(vulnerabilities) > 0
    cve_ids = [v["cve_id"] for v in vulnerabilities]
    assert any("CVE-2022" in id for id in cve_ids)
