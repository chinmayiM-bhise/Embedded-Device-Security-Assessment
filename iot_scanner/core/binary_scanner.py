import os
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Common Magic Bytes for Firmware Signatures
SIGNATURES = {
    "SquashFS": b"hsqs",
    "U-Boot Image": b"\x27\x05\x19\x56",
    "JFFS2": b"\x19\x85",
    "Gzip": b"\x1f\x8b\x08",
    "LZMA": b"\x5d\x00\x00",
    "ELF Binary": b"\x7fELF",
    "CramFS": b"\x45\x3d\xcd\x28",
    "Windows Executable": b"MZ",
}

class BinaryScanner:
   
    def __init__(self, bin_path):
        self.bin_path = bin_path
        self.findings = []
        self.identified_types = []

    def scan_signatures(self):
        """Looks for magic byte signatures in the binary."""
        try:
            with open(self.bin_path, 'rb') as f:
                content = f.read()
                for label, sig in SIGNATURES.items():
                    if sig in content:
                        count = content.count(sig)
                        self.identified_types.append(f"{label} (Found {count} times)")
                        self.findings.append({
                            "type": "Signature Found",
                            "label": label,
                            "description": f"Embedded {label} structure detected in the binary."
                        })
        except Exception as e:
            logger.error(f"Binary signature scan failed: {e}")

    def scan_risky_strings(self):
        try:
            with open(self.bin_path, 'rb') as f:
                
                content = f.read()
                # Find IPs
                ips = re.findall(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
                for ip in set(ips):
                    self.findings.append({
                        "type": "Embedded IP",
                        "label": ip.decode(),
                        "description": "Found a hardcoded IPv4 address in the binary blob."
                    })

                # Find URLs
                urls = re.findall(rb"https?://[^\s\"']+", content)
                for url in set(urls):
                    self.findings.append({
                        "type": "Embedded URL",
                        "label": url.decode()[:50] + "...",
                        "description": "Found a hardcoded URL in the binary blob."
                    })
        except Exception as e:
            logger.error(f"Binary string scan failed: {e}")

    def run_scan(self):
        logger.info(f"Direct binary analysis for: {self.bin_path}")
        self.scan_signatures()
        self.scan_risky_strings()
        return {
            "types": self.identified_types,
            "risks": self.findings
        }

if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 1:
        scanner = BinaryScanner(sys.argv[1])
        print(json.dumps(scanner.run_scan(), indent=2))
    else:
        print("Usage: python binary_scanner.py <path_to_bin>")
