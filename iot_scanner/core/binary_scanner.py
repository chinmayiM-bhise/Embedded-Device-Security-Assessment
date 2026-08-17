import os
import logging
import re
import ipaddress

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# High-confidence magic byte signatures (4 bytes or header-validated)
STRUCTURE_SIGNATURES = {
    "SquashFS (Little-Endian)": b"hsqs",
    "SquashFS (Big-Endian)": b"sqsh",
    "SquashFS (LZMA-Endian)": b"qshs",
    "U-Boot Image Header": b"\x27\x05\x19\x56",
    "CramFS Filesystem": b"\x45\x3d\xcd\x28",
    "ELF Executable/Library": b"\x7fELF",
    "Gzip Compressed Archive": b"\x1f\x8b\x08",
    "LZMA Compressed Stream": b"\x5d\x00\x00\x80\x00",
    "TRX Firmware Header": b"HDR0",
    "TP-Link SafeLoader Header": b"\x00\x00\x00\x00TP-LINK",
}

def is_meaningful_ip(ip_str: str) -> bool:
    """Filters out invalid, loopback, multicast, or placeholder IP addresses."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            return False
        # Filter broadcast/default masks
        if ip_str.endswith(".255") or ip_str.startswith("0.") or ip_str.startswith("255."):
            return False
        return True
    except ValueError:
        return False

class BinaryScanner:
    def __init__(self, bin_path: str):
        self.bin_path = bin_path
        self.structures = []
        self.risks = []

    def scan_structures(self, content: bytes):
        """Identifies embedded container and filesystem structures."""
        for label, sig in STRUCTURE_SIGNATURES.items():
            if sig in content:
                count = content.count(sig)
                first_offset = content.find(sig)
                self.structures.append(f"{label} (Found at offset 0x{first_offset:X}, count: {count})")

    def scan_risky_strings(self, content: bytes):
        """Extracts hardcoded public IPs and external URLs."""
        # 1. IP extraction
        raw_ips = re.findall(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", content)
        seen_ips = set()
        for raw_ip in raw_ips:
            try:
                ip_str = raw_ip.decode('ascii', errors='ignore')
                if ip_str not in seen_ips and is_meaningful_ip(ip_str):
                    seen_ips.add(ip_str)
                    self.risks.append({
                        "type": "Hardcoded IP Address",
                        "label": ip_str,
                        "description": f"Found embedded IPv4 address '{ip_str}' in raw binary."
                    })
            except Exception:
                continue

        # 2. URL extraction (http/https/ftp)
        raw_urls = re.findall(rb"https?://[a-zA-Z0-9.\-_~:/?#\[\]@!$&'()*+,;=%]{8,120}", content)
        seen_urls = set()
        for raw_url in raw_urls:
            try:
                url_str = raw_url.decode('ascii', errors='ignore')
                if url_str not in seen_urls and not url_str.endswith(('.png', '.jpg', '.css', '.js', '.ico')):
                    seen_urls.add(url_str)
                    self.risks.append({
                        "type": "Hardcoded URL Endpoint",
                        "label": url_str[:60] + ("..." if len(url_str) > 60 else ""),
                        "description": f"Found embedded URL endpoint in binary blob: {url_str[:80]}"
                    })
            except Exception:
                continue

    def run_scan(self) -> dict:
        logger.info(f"Direct binary analysis for: {self.bin_path}")
        if not os.path.exists(self.bin_path):
            return {"types": [], "risks": []}

        try:
            with open(self.bin_path, 'rb') as f:
                # Read up to 50MB for forensics to prevent OOM
                content = f.read(50 * 1024 * 1024)
                self.scan_structures(content)
                self.scan_risky_strings(content)
        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")

        return {
            "types": self.structures,
            "risks": self.risks
        }

if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 1:
        scanner = BinaryScanner(sys.argv[1])
        print(json.dumps(scanner.run_scan(), indent=2))
    else:
        print("Usage: python binary_scanner.py <path_to_bin>")
