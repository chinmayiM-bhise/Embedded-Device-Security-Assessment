import os
import json
import sqlite3
import logging
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CACHE_DB_PATH = os.path.join(os.path.dirname(__file__), "cve_cache.db")
CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Core offline snapshot of frequently weaponized IoT CVEs
CURATED_IOT_KEV_SNAPSHOT = {
    "CVE-2022-30065": {"vendor": "BusyBox", "product": "BusyBox", "vulnerabilityName": "BusyBox Heap Buffer Overflow in awk"},
    "CVE-2021-28831": {"vendor": "BusyBox", "product": "BusyBox", "vulnerabilityName": "BusyBox Invalid Free / Denial of Service in decompress_gunzip"},
    "CVE-2018-1000155": {"vendor": "BusyBox", "product": "BusyBox", "vulnerabilityName": "BusyBox Deny-by-DNS Weak Password Processing"},
    "CVE-2022-0778": {"vendor": "OpenSSL", "product": "OpenSSL", "vulnerabilityName": "OpenSSL Infinite Loop in BN_mod_sqrt"},
    "CVE-2021-3449": {"vendor": "OpenSSL", "product": "OpenSSL", "vulnerabilityName": "OpenSSL NULL Pointer Dereference in Signature Algorithms"},
    "CVE-2014-0160": {"vendor": "OpenSSL", "product": "OpenSSL", "vulnerabilityName": "OpenSSL Heartbleed Information Disclosure"},
    "CVE-2020-1968": {"vendor": "OpenSSL", "product": "OpenSSL", "vulnerabilityName": "OpenSSL Raccoon Attack / Key Recovery"},
    "CVE-2019-12255": {"vendor": "Wind River", "product": "VxWorks", "vulnerabilityName": "IPnet TCP Urgent Pointer Buffer Overflow (URGENT/11)"},
    "CVE-2020-11896": {"vendor": "Treck", "product": "Treck TCP/IP", "vulnerabilityName": "Ripple20 Multiple Memory Corruptions"},
    "CVE-2017-17215": {"vendor": "Huawei", "product": "HG532 Router", "vulnerabilityName": "Huawei Router Remote Code Execution (Mirai)"},
    "CVE-2014-8361": {"vendor": "Realtek", "product": "RTL819x Miniigd", "vulnerabilityName": "Realtek SDK UPnP Remote Code Execution"},
}

def init_kev_table():
    try:
        with sqlite3.connect(CACHE_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cisa_kev_cache (
                    cve_id TEXT PRIMARY KEY,
                    vendor TEXT,
                    product TEXT,
                    vulnerability_name TEXT,
                    updated_at TIMESTAMP
                )
            """)
            conn.commit()
    except Exception as e:
        logger.debug(f"KEV table init error: {e}")

init_kev_table()

class CISAKEVClient:
    def __init__(self, ttl_days: int = 14):
        self.ttl_days = ttl_days
        self._populate_initial_cache()

    def _populate_initial_cache(self):
        """Populates the database with the curated snapshot if cache is empty."""
        try:
            with sqlite3.connect(CACHE_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM cisa_kev_cache")
                count = cursor.fetchone()[0]
                if count == 0:
                    now = datetime.now(timezone.utc).isoformat()
                    for cve_id, info in CURATED_IOT_KEV_SNAPSHOT.items():
                        cursor.execute(
                            "INSERT OR IGNORE INTO cisa_kev_cache (cve_id, vendor, product, vulnerability_name, updated_at) VALUES (?, ?, ?, ?, ?)",
                            (cve_id, info["vendor"], info["product"], info["vulnerabilityName"], now)
                        )
                    conn.commit()
        except Exception as e:
            logger.debug(f"Initial KEV cache populate error: {e}")

    def refresh_from_cisa_feed(self) -> bool:
        """Fetches the complete authoritative CISA KEV catalog over HTTPS."""
        try:
            req = urllib.request.Request(
                CISA_KEV_FEED_URL,
                headers={"User-Agent": "IoT-Security-Scanner/1.2"}
            )
            with urllib.request.urlopen(req, timeout=8) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    vulns = data.get("vulnerabilities", [])
                    now = datetime.now(timezone.utc).isoformat()
                    with sqlite3.connect(CACHE_DB_PATH) as conn:
                        cursor = conn.cursor()
                        for v in vulns:
                            cve_id = v.get("cveID")
                            if cve_id:
                                cursor.execute(
                                    "INSERT OR REPLACE INTO cisa_kev_cache (cve_id, vendor, product, vulnerability_name, updated_at) VALUES (?, ?, ?, ?, ?)",
                                    (cve_id, v.get("vendorProject", "Unknown"), v.get("product", "Unknown"), v.get("vulnerabilityName", "Active Exploit in the Wild"), now)
                                )
                        conn.commit()
                    logger.info(f"Successfully synchronized {len(vulns)} CVEs from official CISA KEV feed.")
                    return True
        except Exception as e:
            logger.debug(f"Could not refresh CISA KEV feed online (using cached catalog): {e}")
        return False

    def is_known_exploited(self, cve_id: str) -> bool:
        """Checks if a CVE is cataloged in CISA Known Exploited Vulnerabilities."""
        if not cve_id or cve_id.startswith("POLICY-") or cve_id == "CVE-UNKNOWN":
            return False
        
        try:
            with sqlite3.connect(CACHE_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT cve_id FROM cisa_kev_cache WHERE cve_id = ?", (cve_id,))
                return cursor.fetchone() is not None
        except Exception:
            return cve_id in CURATED_IOT_KEV_SNAPSHOT

    def get_kev_details(self, cve_id: str) -> dict:
        """Retrieves CISA KEV metadata for an actively exploited CVE."""
        if not self.is_known_exploited(cve_id):
            return None

        try:
            with sqlite3.connect(CACHE_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT vendor, product, vulnerability_name FROM cisa_kev_cache WHERE cve_id = ?", (cve_id,))
                row = cursor.fetchone()
                if row:
                    return {
                        "is_cisa_kev": True,
                        "vendor": row[0],
                        "product": row[1],
                        "vulnerability_name": row[2],
                        "alert": "🚨 CISA KEV: Actively weaponized and exploited in the wild. Immediate patching required."
                    }
        except Exception:
            pass

        if cve_id in CURATED_IOT_KEV_SNAPSHOT:
            info = CURATED_IOT_KEV_SNAPSHOT[cve_id]
            return {
                "is_cisa_kev": True,
                "vendor": info["vendor"],
                "product": info["product"],
                "vulnerability_name": info["vulnerabilityName"],
                "alert": "🚨 CISA KEV: Actively weaponized and exploited in the wild. Immediate patching required."
            }

        return None
