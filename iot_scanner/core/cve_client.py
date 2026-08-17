import os
import json
import sqlite3
import logging
import urllib.request
import urllib.error
import re
from datetime import datetime, timedelta, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CACHE_DB_PATH = os.path.join(os.path.dirname(__file__), "cve_cache.db")
LOCAL_CVE_DB_PATH = os.path.join(os.path.dirname(__file__), "cve_db.json")

def init_cache_db():
    """Initializes the SQLite CVE cache database table."""
    try:
        with sqlite3.connect(CACHE_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    component TEXT,
                    version TEXT,
                    response_json TEXT,
                    updated_at TIMESTAMP,
                    PRIMARY KEY (component, version)
                )
            """)
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to initialize CVE cache DB: {e}")

init_cache_db()

class CVEClient:
    def __init__(self, cache_ttl_days: int = 7):
        self.cache_ttl_days = cache_ttl_days
        self.local_db = self._load_local_db()

    def _load_local_db(self) -> dict:
        try:
            if os.path.exists(LOCAL_CVE_DB_PATH):
                with open(LOCAL_CVE_DB_PATH, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load fallback local CVE database: {e}")
        return {}

    def _get_from_cache(self, component: str, version: str):
        try:
            with sqlite3.connect(CACHE_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT response_json, updated_at FROM cve_cache WHERE component = ? AND version = ?",
                    (component.lower(), (version or "").lower())
                )
                row = cursor.fetchone()
                if row:
                    cached_json, updated_at_str = row
                    updated_at = datetime.fromisoformat(updated_at_str)
                    if datetime.now(timezone.utc) - updated_at < timedelta(days=self.cache_ttl_days):
                        return json.loads(cached_json)
        except Exception as e:
            logger.debug(f"Cache lookup error: {e}")
        return None

    def _save_to_cache(self, component: str, version: str, data: list):
        try:
            with sqlite3.connect(CACHE_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO cve_cache (component, version, response_json, updated_at) VALUES (?, ?, ?, ?)",
                    (component.lower(), (version or "").lower(), json.dumps(data), datetime.now(timezone.utc).isoformat())
                )
                conn.commit()
        except Exception as e:
            logger.debug(f"Cache save error: {e}")

    def _extract_cve_id(self, item: dict) -> str:
        item_id = item.get("id", "")
        # Check aliases
        for alias in item.get("aliases", []):
            if alias.startswith("CVE-"):
                return alias
        # Extract CVE from ID string (e.g. ALPINE-CVE-2021-28831)
        cve_match = re.search(r"CVE-\d{4}-\d{4,}", item_id)
        if cve_match:
            return cve_match.group(0)
        # Check details for CVE
        details = item.get("details", "")
        cve_match_details = re.search(r"CVE-\d{4}-\d{4,}", details)
        if cve_match_details:
            return cve_match_details.group(0)
        return item_id or "CVE-UNKNOWN"

    def _parse_cvss_score(self, item: dict) -> tuple:
        """Parses CVSS score and calculates numeric rating and severity label."""
        severities = item.get("severity", [])
        for s in severities:
            score_str = s.get("score", "")
            if "CVSS:" in score_str:
                # Basic heuristic estimation from CVSS vector
                # Availability / Confidentiality / Integrity High -> 7.5+
                impact_count = score_str.count(":H")
                if impact_count >= 3:
                    return 9.8, "Critical", score_str
                elif impact_count == 2:
                    return 8.1, "High", score_str
                elif impact_count == 1:
                    return 6.5, "Medium", score_str
                return 5.3, "Medium", score_str

        # Fallback based on text heuristics
        details = (item.get("details", "") + " " + item.get("summary", "")).lower()
        if any(w in details for w in ["remote code execution", "rce", "unauthenticated", "buffer overflow", "command injection"]):
            return 8.8, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        elif any(w in details for w in ["denial of service", "crash", "infinite loop", "null pointer"]):
            return 5.9, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        return 5.0, "Medium", "N/A"

    def query_osv(self, component: str, version: str) -> list:
        """Queries Google OSV.dev API for vulnerabilities."""
        url = "https://api.osv.dev/v1/query"
        payload = {"package": {"name": component.lower()}}
        if version and version != "Unknown":
            payload["version"] = version

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "IoT-Firmware-Scanner/1.2"}
            )
            with urllib.request.urlopen(req, timeout=6) as response:
                if response.status == 200:
                    raw_data = json.loads(response.read().decode("utf-8"))
                    vulns = raw_data.get("vulns", [])
                    results = []
                    seen_cves = set()
                    
                    # Cap to top 15 most relevant vulnerabilities
                    for v in vulns[:15]:
                        cve_id = self._extract_cve_id(v)
                        if cve_id in seen_cves:
                            continue
                        seen_cves.add(cve_id)
                        
                        cvss_score, severity, cvss_vector = self._parse_cvss_score(v)
                        description = v.get("summary") or v.get("details", "No description available.")
                        if len(description) > 280:
                            description = description[:277] + "..."

                        results.append({
                            "cve_id": cve_id,
                            "severity": severity,
                            "cvss_score": cvss_score,
                            "cvss_vector": cvss_vector,
                            "description": description
                        })
                    return results
        except Exception as e:
            logger.debug(f"OSV API query failed for {component} ({version}): {e}")
        return []

    def get_vulnerabilities(self, component: str, version: str = "Unknown") -> list:
        """
        Retrieves vulnerabilities with caching: Cache -> OSV API -> Local DB Fallback.
        """
        # 1. Check local cache
        cached = self._get_from_cache(component, version)
        if cached is not None:
            logger.info(f"Retrieved {len(cached)} CVEs for {component} v{version} from local cache.")
            return cached

        # 2. Query OSV.dev API
        osv_results = self.query_osv(component, version)
        if osv_results:
            logger.info(f"Fetched {len(osv_results)} real-time CVEs for {component} v{version} from OSV.dev.")
            self._save_to_cache(component, version, osv_results)
            return osv_results

        # 3. Fallback to Local CVE DB
        local_results = []
        if component in self.local_db:
            for item in self.local_db[component]:
                local_results.append({
                    "cve_id": item.get("id", "CVE-UNKNOWN"),
                    "severity": item.get("severity", "Medium"),
                    "cvss_score": item.get("cvss", 5.0),
                    "cvss_vector": item.get("cvss_vector", "N/A"),
                    "description": item.get("description", "Vulnerability found in local database.")
                })
            logger.info(f"Retrieved {len(local_results)} CVEs for {component} from local fallback DB.")
            self._save_to_cache(component, version, local_results)
            return local_results

        return []
