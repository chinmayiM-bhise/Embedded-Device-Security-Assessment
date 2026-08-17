import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

OWASP_IOT_TOP_10 = [
    {
        "id": "I1",
        "title": "Weak, Guessable, or Hardcoded Passwords",
        "description": "Exposed password hashes, hardcoded credentials, or default administrative passwords.",
        "standard": "OWASP IoT Top 10 (I1) / NIST SP 800-213 (2.1)"
    },
    {
        "id": "I2",
        "title": "Insecure Network Services",
        "description": "Unencrypted network listening services such as unauthenticated Telnet daemons.",
        "standard": "OWASP IoT Top 10 (I2) / NIST SP 800-213 (2.2)"
    },
    {
        "id": "I3",
        "title": "Insecure Ecosystem Interfaces & Vulnerable Calls",
        "description": "High-severity vulnerabilities, command injection risks, and unsafe libc function calls.",
        "standard": "OWASP IoT Top 10 (I3) / NIST SP 800-213 (2.3)"
    },
    {
        "id": "I4",
        "title": "Lack of Device Hardening & Binary Mitigations",
        "description": "Compiled binaries lacking modern compiler mitigations (NX/DEP, ASLR/PIE, Stack Canaries).",
        "standard": "OWASP IoT Top 10 (I4) / NIST SP 800-213 (2.4)"
    },
    {
        "id": "I5",
        "title": "Use of Insecure or Outdated Components",
        "description": "Software packages (BusyBox, OpenSSL, Kernel) with unpatched Common Vulnerabilities & Exposures.",
        "standard": "OWASP IoT Top 10 (I5) / NIST SP 800-213 (2.5)"
    },
    {
        "id": "I6",
        "title": "Insufficient Privacy Protection & Key Disclosure",
        "description": "Hardcoded private RSA keys, AWS/Google API keys, and cryptographic secrets in filesystem.",
        "standard": "OWASP IoT Top 10 (I6) / NIST SP 800-213 (2.6)"
    },
    {
        "id": "I7",
        "title": "Insecure Default Settings & Permissions",
        "description": "Overly permissive file permissions (chmod 777) and dangerous default configuration files.",
        "standard": "OWASP IoT Top 10 (I7) / NIST SP 800-213 (2.7)"
    },
    {
        "id": "I8",
        "title": "Malicious Payloads & Backdoor Mechanisms",
        "description": "Presence of known botnets (Mirai, Gafgyt, Mozi), reverse shells, or backdoor scripts.",
        "standard": "OWASP IoT Top 10 (I8) / NIST SP 800-213 (2.8)"
    }
]

def evaluate_owasp_compliance(scan_results: dict) -> dict:
    """
    Evaluates firmware scan findings against the OWASP IoT Top 10 and NIST SP 800-213 standards.
    Returns compliance status, passing percentage, and per-category violation details.
    """
    extraction_failed = scan_results.get("extraction_status") == "FAILED" or not scan_results.get("has_rootfs", True)

    if extraction_failed:
        return {
            "compliance_score": "N/A",
            "status": "UNASSESSED",
            "passed_categories": 0,
            "total_categories": len(OWASP_IOT_TOP_10),
            "categories": [
                {**cat, "status": "N/A", "findings_count": 0, "violations": ["Extraction failed / Filesystem unparseable"]}
                for cat in OWASP_IOT_TOP_10
            ]
        }

    secrets = scan_results.get("secrets", [])
    statics = scan_results.get("static_analysis", [])
    vulns = scan_results.get("vulnerability_scan", {}).get("vulnerabilities", [])
    hardening = scan_results.get("hardening_analysis", [])
    malware = scan_results.get("malware_analysis", [])

    category_eval = []
    passed_count = 0

    for cat in OWASP_IOT_TOP_10:
        violations = []
        c_id = cat["id"]

        # I1: Passwords & Credentials
        if c_id == "I1":
            for s in statics:
                if s.get("type") in ["Credential Audit", "Sensitive File"] and "shadow" in s.get("file", ""):
                    violations.append(f"Exposed password hash in {s.get('file')}")
            for sec in secrets:
                if "password" in sec.get("type", "").lower() or "admin:admin" in sec.get("match", ""):
                    violations.append(f"Hardcoded credential: {sec.get('type')}")

        # I2: Network Services
        elif c_id == "I2":
            for v in vulns:
                if v.get("component") == "Telnet":
                    violations.append("Cleartext Telnet daemon detected and enabled.")

        # I3: Ecosystem Interfaces & Unsafe Libc Functions
        elif c_id == "I3":
            for h in hardening:
                for d in h.get("dangerous_functions", []):
                    if d.get("severity") in ["Critical", "High"]:
                        violations.append(f"Unsafe C library call '{d['function']}' in {os.path.basename(h.get('file', ''))}")
            for v in vulns:
                if v.get("severity") == "Critical":
                    violations.append(f"Critical Vulnerability {v.get('cve_id')} in {v.get('component')}")

        # I4: Device Hardening & Mitigations
        elif c_id == "I4":
            if hardening:
                missing_nx = [h for h in hardening if not h.get("nx")]
                missing_canary = [h for h in hardening if not h.get("canary")]
                if missing_nx:
                    violations.append(f"{len(missing_nx)} binaries lack NX/DEP (Executable Stack Protection)")
                if missing_canary:
                    violations.append(f"{len(missing_canary)} binaries lack Stack Canaries (__stack_chk_fail)")

        # I5: Outdated Components & CVEs
        elif c_id == "I5":
            if vulns:
                violations.append(f"{len(vulns)} Common Vulnerabilities and Exposures (CVEs) present in software stack")

        # I6: Privacy & Exposed Secrets
        elif c_id == "I6":
            for sec in secrets:
                if any(k in sec.get("type", "").lower() for k in ["key", "token", "entropy", "rsa"]):
                    violations.append(f"Discovered {sec.get('type')} in {sec.get('file')}")

        # I7: Insecure Permissions
        elif c_id == "I7":
            for s in statics:
                if "777" in s.get("description", ""):
                    violations.append("Insecure file permissions (chmod 777)")

        # I8: Malware & Backdoors
        elif c_id == "I8":
            for m in malware:
                violations.append(f"Malware hit: {m.get('malware_family', 'Threat detected')} in {m.get('file')}")
            for s in statics:
                if "backdoor" in s.get("description", "").lower():
                    violations.append(f"Suspicious backdoor string in {s.get('file')}")

        is_pass = len(violations) == 0
        if is_pass:
            passed_count += 1

        category_eval.append({
            "id": cat["id"],
            "title": cat["title"],
            "standard": cat["standard"],
            "status": "PASS" if is_pass else "FAIL",
            "findings_count": len(violations),
            "violations": violations[:5] # cap to top 5 for readability
        })

    compliance_percentage = int((passed_count / len(OWASP_IOT_TOP_10)) * 100)

    return {
        "compliance_score": f"{compliance_percentage}%",
        "passed_categories": passed_count,
        "total_categories": len(OWASP_IOT_TOP_10),
        "status": "COMPLIANT" if compliance_percentage >= 80 else ("PARTIAL" if compliance_percentage >= 50 else "NON_COMPLIANT"),
        "categories": category_eval
    }
