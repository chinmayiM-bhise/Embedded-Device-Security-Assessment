import uuid
import json
from datetime import datetime, timezone

def generate_cyclonedx_sbom(components: list, vulnerabilities: list, firmware_name: str = "firmware.bin") -> dict:
    """
    Generates an industry-standard Software Bill of Materials (SBOM) 
    in CycloneDX 1.5 JSON specification format.
    """
    bom_serial = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    cdx_components = []
    component_purl_map = {}

    for comp in components:
        c_name = comp.get("name", "unknown").lower()
        c_version = comp.get("version", "unknown")
        purl = f"pkg:generic/{c_name}@{c_version}"
        component_purl_map[comp.get("name", "")] = purl

        comp_type = "operating-system" if "kernel" in c_name else ("library" if c_name in ["openssl", "zlib", "libpng"] else "application")
        
        cdx_components.append({
            "type": comp_type,
            "name": comp.get("name", "unknown"),
            "version": c_version,
            "purl": purl,
            "evidence": {
                "occurrences": [
                    {
                        "location": comp.get("source", "N/A")
                    }
                ]
            }
        })

    cdx_vulnerabilities = []
    for vuln in vulnerabilities:
        cve_id = vuln.get("cve_id", "CVE-UNKNOWN")
        comp_name = vuln.get("component", "")
        purl = component_purl_map.get(comp_name, f"pkg:generic/{comp_name.lower()}@{vuln.get('version', 'unknown')}")
        
        cvss_score = vuln.get("cvss_score", 5.0)
        severity = vuln.get("severity", "Medium").lower()
        vector = vuln.get("cvss_vector", "")

        cdx_vuln = {
            "id": cve_id,
            "source": {
                "name": "OSV / NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else f"https://osv.dev/vulnerability/{cve_id}"
            },
            "ratings": [
                {
                    "score": float(cvss_score) if isinstance(cvss_score, (int, float)) else 5.0,
                    "severity": severity if severity in ["critical", "high", "medium", "low", "info"] else "medium",
                    "method": "CVSSv31",
                    "vector": vector if vector != "N/A" else None
                }
            ],
            "description": vuln.get("description", ""),
            "recommendation": vuln.get("remediation", "Update to the latest patched version."),
            "affects": [
                {
                    "ref": purl
                }
            ]
        }
        cdx_vulnerabilities.append(cdx_vuln)

    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": bom_serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "IoT Firmware Security Scanner",
                    "name": "Embedded Device Security Assessment Engine",
                    "version": "1.2.0"
                }
            ],
            "component": {
                "type": "firmware",
                "name": firmware_name,
                "version": "1.0.0"
            }
        },
        "components": cdx_components,
        "vulnerabilities": cdx_vulnerabilities
    }

    return sbom

def save_sbom_json(sbom_data: dict, output_path: str):
    """Saves SBOM dictionary to formatted JSON file."""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sbom_data, f, indent=2)
    return output_path
