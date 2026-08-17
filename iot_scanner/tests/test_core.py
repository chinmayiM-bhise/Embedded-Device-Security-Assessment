import pytest
import os
import shutil
import zipfile
from iot_scanner.core.secret_scanner import SecretScanner
from iot_scanner.core.static_analyzer import StaticAnalyzer
from iot_scanner.core.vulnerability_scanner import VulnerabilityScanner
from iot_scanner.core.malware_scanner import MalwareScanner
from iot_scanner.core.binary_scanner import BinaryScanner
from iot_scanner.core.hardening_analyzer import HardeningAnalyzer
from iot_scanner.core.extractor import extract_firmware, validate_rootfs
from iot_scanner.core.report_generator import calculate_security_score
from iot_scanner.core.cve_client import CVEClient
from iot_scanner.core.cisa_kev import CISAKEVClient
from iot_scanner.core.compliance import evaluate_owasp_compliance
from iot_scanner.core.sbom_generator import generate_cyclonedx_sbom
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

def test_yara_threat_suite(tmp_path):
    """Test YARA rule detections across Mirai, Gafgyt, and Mozi."""
    threat_dir = tmp_path / "threats"
    threat_dir.mkdir()
    
    (threat_dir / "mirai_bot").write_bytes(b"POST /cdn-cgi/ listen 0.0.0.0: X-Target: 192.168.1.1 X-Token: abc")
    (threat_dir / "gafgyt_bot").write_bytes(b"Gafgyt BASHLITE PING PONG SCANNER ON")
    (threat_dir / "mozi_bot").write_bytes(b"[hpldf] [ss] 8:count64: d1:ad2:id20:")

    scanner = MalwareScanner(str(threat_dir))
    findings = scanner.run_scan()
    assert len(findings) >= 3
    all_families = [f["malware_family"] for f in findings]
    assert any("Mirai" in fam for fam in all_families)
    assert any("Gafgyt" in fam for fam in all_families)
    assert any("Mozi" in fam for fam in all_families)

def test_vulnerability_scanner():
    """Test that software components and CVEs are identified."""
    scanner = VulnerabilityScanner(TEST_DIR)
    results = scanner.run_scan()
    
    found_components = [c["name"] for c in results["components"]]
    assert "BusyBox" in found_components
    assert "OpenSSL" in found_components
    
    vulnerabilities = results["vulnerabilities"]
    assert len(vulnerabilities) > 0

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
    
    inner_zip = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner_zip, 'w') as zf:
        for root, _, files in os.walk(inner_dir):
            for file in files:
                p = os.path.join(root, file)
                zf.write(p, os.path.relpath(p, inner_dir))

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

def test_cve_client_and_cache():
    """Test CVEClient retrieval and caching."""
    client = CVEClient(cache_ttl_days=1)
    vulns = client.get_vulnerabilities("BusyBox", "1.33.1")
    assert len(vulns) > 0
    cached_vulns = client.get_vulnerabilities("BusyBox", "1.33.1")
    assert len(cached_vulns) == len(vulns)

def test_cisa_kev_catalog():
    """Test CISA KEV detection for actively weaponized CVEs."""
    kev_client = CISAKEVClient()
    assert kev_client.is_known_exploited("CVE-2022-30065") is True
    assert kev_client.is_known_exploited("CVE-2014-0160") is True
    assert kev_client.is_known_exploited("CVE-FAKE-9999-0000") is False
    meta = kev_client.get_kev_details("CVE-2022-30065")
    assert meta is not None
    assert "BusyBox" in meta["vendor"]

def test_owasp_compliance_evaluator():
    """Test OWASP IoT Top 10 compliance engine."""
    mock_results = {
        "has_rootfs": True,
        "extraction_status": "SUCCESS",
        "secrets": [{"type": "Google API Key", "file": "etc/config"}],
        "static_analysis": [{"type": "Sensitive File", "file": "etc/shadow"}],
        "vulnerability_scan": {
            "components": [{"name": "BusyBox", "version": "1.33.1"}],
            "vulnerabilities": [{"cve_id": "CVE-2022-30065", "severity": "Critical", "component": "BusyBox"}]
        },
        "hardening_analysis": [{"file": "bin/busybox", "nx": False, "canary": False, "dangerous_functions": []}],
        "malware_analysis": []
    }
    compliance = evaluate_owasp_compliance(mock_results)
    assert compliance["status"] in ["COMPLIANT", "PARTIAL", "NON_COMPLIANT"]
    assert len(compliance["categories"]) == 8
    cat_ids = [c["id"] for c in compliance["categories"]]
    assert "I1" in cat_ids
    assert "I4" in cat_ids
    assert "I6" in cat_ids

def test_sbom_generator():
    """Test CycloneDX 1.5 SBOM JSON generation."""
    components = [
        {"name": "busybox", "version": "1.33.1", "source": "usr/bin/busybox"},
        {"name": "openssl", "version": "1.1.1f", "source": "usr/bin/openssl"}
    ]
    vulnerabilities = [
        {
            "cve_id": "CVE-2022-30065",
            "component": "busybox",
            "version": "1.33.1",
            "severity": "High",
            "cvss_score": 7.8,
            "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "description": "BusyBox heap buffer overflow."
        }
    ]
    sbom = generate_cyclonedx_sbom(components, vulnerabilities, "test_firmware.bin")
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert len(sbom["components"]) == 2
    assert len(sbom["vulnerabilities"]) == 1
    assert sbom["components"][0]["purl"] == "pkg:generic/busybox@1.33.1"

def test_package_manifest_parser(tmp_path):
    """Test parsing OPKG package manifests from rootfs."""
    opkg_dir = tmp_path / "usr" / "lib" / "opkg"
    opkg_dir.mkdir(parents=True)
    status_file = opkg_dir / "status"
    status_file.write_text(
        "Package: dnsmasq\nVersion: 2.86-1\nStatus: install user installed\n\n"
        "Package: dropbear\nVersion: 2022.82-1\nStatus: install user installed\n\n"
    )
    scanner = VulnerabilityScanner(str(tmp_path))
    scanner.identify_components()
    comp_names = [c["name"] for c in scanner.components]
    assert "dnsmasq" in comp_names
    assert "dropbear" in comp_names

def test_hardening_analyzer_architecture():
    """Test HardeningAnalyzer on workspace."""
    analyzer = HardeningAnalyzer(TEST_DIR)
    findings = analyzer.run_analysis()
    assert isinstance(findings, list)
