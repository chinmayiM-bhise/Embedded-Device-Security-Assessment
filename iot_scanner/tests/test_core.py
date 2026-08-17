import pytest
import os
import shutil
import zipfile
from iot_scanner.core.secret_scanner import SecretScanner
from iot_scanner.core.static_analyzer import StaticAnalyzer
from iot_scanner.core.vulnerability_scanner import VulnerabilityScanner
from iot_scanner.core.malware_scanner import MalwareScanner
from iot_scanner.core.binary_scanner import BinaryScanner
from iot_scanner.core.extractor import extract_firmware, validate_rootfs
from iot_scanner.core.report_generator import calculate_security_score
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
    
    found_types = [f["type"] for f in findings]
    assert "Google API Key" in found_types
    assert "Generic Password/Token" in found_types
    assert "SSH Private Key" in found_types

def test_static_analyzer():
    """Test that sensitive files are identified."""
    analyzer = StaticAnalyzer(TEST_DIR)
    findings = analyzer.run_analysis()
    
    found_files = [f["file"] for f in findings if f["type"] == "Sensitive File"]
    assert "/etc/shadow" in found_files
    assert "/etc/passwd" in found_files

def test_static_analyzer_dangerous_functions():
    """Test that dangerous functions in binaries are detected."""
    analyzer = StaticAnalyzer(TEST_DIR)
    findings = analyzer.run_analysis()
    
    vulnerable_findings = [f for f in findings if f["type"] == "Dangerous Function" and "vulnerable_app" in f["file"]]
    assert len(vulnerable_findings) > 0
    description = vulnerable_findings[0]["description"]
    assert "strcpy" in description
    assert "system" in description

def test_malware_scanner():
    """Test that malware indicators are detected."""
    scanner = MalwareScanner(TEST_DIR)
    findings = scanner.run_scan()
    
    assert len(findings) > 0
    assert any("bot.sh" in f["file"] for f in findings)
    assert any(any(d["method"] == "Heuristic" for d in f.get("detections", [])) for f in findings)

def test_vulnerability_scanner():
    """Test that software components and CVEs are identified."""
    scanner = VulnerabilityScanner(TEST_DIR)
    results = scanner.run_scan()
    
    found_components = [c["name"] for c in results["components"]]
    assert "BusyBox" in found_components
    assert "OpenSSL" in found_components
    
    vulnerabilities = results["vulnerabilities"]
    assert len(vulnerabilities) > 0
    cve_ids = [v["cve_id"] for v in vulnerabilities]
    assert any("CVE-2022" in id for id in cve_ids)

def test_rootfs_validation():
    """Test rootfs detection on a valid directory vs dummy file."""
    has_rootfs, count, root_dir = validate_rootfs(TEST_DIR)
    assert has_rootfs is True
    assert count > 3

    dummy_dir = "test_dummy_empty"
    os.makedirs(dummy_dir, exist_ok=True)
    with open(os.path.join(dummy_dir, "random.blob"), "wb") as f:
        f.write(b"random binary data")
    has_rootfs_dummy, count_dummy, _ = validate_rootfs(dummy_dir)
    assert has_rootfs_dummy is False
    shutil.rmtree(dummy_dir)

def test_nested_archive_extraction(tmp_path):
    """Test extracting a zip archive containing an inner firmware image."""
    inner_dir = tmp_path / "inner_root"
    inner_dir.mkdir()
    create_mock_firmware(str(inner_dir))
    
    # Pack inner into inner.zip
    inner_zip = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner_zip, 'w') as zf:
        for root, _, files in os.walk(inner_dir):
            for file in files:
                p = os.path.join(root, file)
                zf.write(p, os.path.relpath(p, inner_dir))

    # Pack inner.zip into outer.zip
    outer_zip = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer_zip, 'w') as zf:
        zf.write(inner_zip, "inner_payload.zip")

    dest_dir = tmp_path / "extracted_outer"
    meta = extract_firmware(str(outer_zip), str(dest_dir))
    assert meta["has_rootfs"] is True
    assert meta["status"] == "SUCCESS"

def test_score_fail_safe_guard():
    """Verify that failed extraction yields 'N/A' score rather than a false 100/100."""
    failed_data = {
        "extraction_status": "FAILED",
        "has_rootfs": False,
        "vulnerability_scan": {"components": [], "vulnerabilities": []},
        "secrets": [],
        "malware_analysis": [],
        "hardening_analysis": []
    }
    score = calculate_security_score(failed_data)
    assert score == "N/A"
