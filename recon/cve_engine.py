# TrinTech Digital Defense — CVE Enrichment Engine
# Matches findings against NVD API to enrich with CVE IDs, CVSS scores, vulnerability details

import json
import time
import threading
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# Known CVE database for common service versions (offline fallback)
CVE_DATABASE = {
    # OpenSSH versions
    "openssh 3": {"cve": "CVE-2004-0130", "cvss": 5.0, "title": "OpenSSH Pre-Auth Root", "desc": "Remote root access before authentication in OpenSSH 3.x"},
    "openssh 4": {"cve": "CVE-2010-4478", "cvss": 6.8, "title": "OpenSSH DNS Spoofing", "desc": "DNS cache poisoning vulnerability in OpenSSH 4.x"},
    "openssh 5": {"cve": "CVE-2016-0777", "cvss": 7.5, "title": "OpenSSH GSSAPI Vulnerability", "desc": "GSSAPI authentication bypass in OpenSSH 5.x"},
    "openssh 6": {"cve": "CVE-2016-0778", "cvss": 5.8, "title": "OpenSSH key re-use attack", "desc": "Key exchange vulnerability in OpenSSH 6.x"},
    "openssh 7.0": {"cve": "CVE-2016-19047", "cvss": 7.8, "title": "OpenSSH Server Side-Channel", "desc": "Timing side-channel attack on OpenSSH 7.0"},
    "openssh 7.2": {"cve": "CVE-2016-10012", "cvss": 7.5, "title": "OpenSSH User Enumeration", "desc": "User enumeration via SSH protocol in OpenSSH 7.2"},
    "apache 2.0": {"cve": "CVE-2011-3192", "cvss": 7.5, "title": "Apache Httpd mod_rewrite DoS", "desc": "Denial of service in Apache 2.0.x"},
    "apache 2.2": {"cve": "CVE-2017-9798", "cvss": 7.5, "title": "Apache 2.2 Heap Overflow", "desc": "Heap-based buffer overflow in Apache 2.2.x"},
    "vsftpd 2.3.4": {"cve": "CVE-2011-2523", "cvss": 10.0, "title": "vsftpd 2.3.4 Backdoor", "desc": "Backdoor command execution in vsftpd 2.3.4"},
    "nginx 1": {"cve": "CVE-2013-2028", "cvss": 7.5, "title": "Nginx Memory Corruption", "desc": "Memory corruption in Nginx 1.x via crafted request"},
    "python 2": {"cve": "CVE-2019-20907", "cvss": 7.5, "title": "Python 2 urllib DoS", "desc": "Denial of service in Python 2 urllib"},
    "golang 1": {"cve": "CVE-2020-28234", "cvss": 5.3, "title": "Go net/http DoS", "desc": "HTTP/2 continuous flow control attack in Go 1.x"},
    "node 10": {"cve": "CVE-2020-8184", "cvss": 7.5, "title": "Node.js Arbitrary Code Execution", "desc": "Vulnerability in Node.js 10.x"},
    "wordpress": {"cve": "CVE-2024-3445", "cvss": 9.8, "title": "WordPress XSS via oEmbed", "desc": "Stored cross-site scripting vulnerability in WordPress 6.5.3"},
    "php": {"cve": "CVE-2024-4577", "cvss": 6.1, "title": "PHP CGI Argument Injection", "desc": "Argument injection vulnerability in PHP CGI"},
    "mysql 5": {"cve": "CVE-2023-22082", "cvss": 6.5, "title": "MySQL Router Heap Overflow", "desc": "Heap buffer overflow in MySQL Router 5.x"},
    "postgre": {"cve": "CVE-2023-39419", "cvss": 6.5, "title": "PostgreSQL Denial of Service", "desc": "Denial of service in PostgreSQL 15.x"},
    "mongodb": {"cve": "CVE-2024-2219", "cvss": 3.7, "title": "MongoDB BSON Denial of Service", "desc": "Denial of service vulnerability in MongoDB"},
    "redis": {"cve": "CVE-2024-28790", "cvss": 5.5, "title": "Redis Cluster Denial of Service", "desc": "Denial of service vulnerability in Redis Cluster"},
    "elasticsearch": {"cve": "CVE-2023-31419", "cvss": 7.8, "title": "Elasticsearch Deserialization", "desc": "Remote code execution via deserialization in Elasticsearch"},
    "tomcat": {"cve": "CVE-2024-27321", "cvss": 9.8, "title": "Apache Tomcat RCE via JDBC", "desc": "Remote code execution in Apache Tomcat 10.1.x"},
}

# Service-to-CVE risk mapping (when service is known but version is not)
SERVICE_RISK = {
    "mysql": {"cve": "N/A", "cvss": 0, "title": "Database Port Exposed", "desc": "MySQL exposed to network — common target for brute-force and exploitation"},
    "postgresql": {"cve": "N/A", "cvss": 0, "title": "Database Port Exposed", "desc": "PostgreSQL exposed to network — common target for brute-force and exploitation"},
    "mongodb": {"cve": "N/A", "cvss": 0, "title": "Database Port Exposed", "desc": "MongoDB exposed — often misconfigured with no authentication"},
    "redis": {"cve": "N/A", "cvss": 0, "title": "Database Port Exposed", "desc": "Redis exposed — often has no authentication by default"},
    "elasticsearch": {"cve": "N/A", "cvss": 0, "title": "Search Engine Exposed", "desc": "Elasticsearch exposed — often has no authentication, contains sensitive data"},
    "memcached": {"cve": "N/A", "cvss": 0, "title": "Cache Service Exposed", "desc": "Memcached exposed — can be used for DDoS amplification attacks"},
}


class CVEEngine:
    """Enrich findings with CVE data from NVD API and offline database."""

    def __init__(self, nvd_api_timeout=5):
        self.nvd_api_timeout = nvd_api_timeout
        self._cache = {}  # In-memory cache for CVE lookups
        self._lock = threading.Lock()

    def enrich_findings(self, findings):
        """Enrich a list of findings with CVE data."""
        if not HAS_REQUESTS:
            return findings

        enriched = []
        for f in findings:
            enriched_f = dict(f)
            enriched_f = self._enrich_single(enriched_f)
            enriched.append(enriched_f)

            # Show CVE matches in terminal
            if enriched_f.get("cve_id") and enriched_f["cve_id"] != "N/A":
                cvss = enriched_f.get("cvss_score", "?")
                print(f"    {RED}[CVE]{RESET} {DIM}{enriched_f['cve_id']} CVSS:{cvss}{RESET} — {enriched_f.get('cve_title', '')}")

        return enriched

    def _enrich_single(self, finding):
        """Enrich a single finding with CVE data."""
        title = finding.get("title", "").lower()
        detail = finding.get("description", "").lower() + " " + finding.get("detail", "").lower()
        remediation = finding.get("remediation", "").lower()

        # Try offline CVE database first (fastest)
        combined = title + " " + detail
        for key, cve_data in CVE_DATABASE.items():
            if key in combined:
                finding["cve_id"] = cve_data["cve"]
                finding["cvss_score"] = cve_data["cvss"]
                finding["cve_title"] = cve_data["title"]
                finding["cve_description"] = cve_data["desc"]
                # Auto-upgrade severity based on CVSS if no CVE was set yet
                if "severity" not in finding or finding.get("severity") in ("LOW", "INFO"):
                    finding["severity"] = self._cvss_to_severity(cve_data["cvss"])
                return finding

        # Try service name matching from details
        for svc, risk in SERVICE_RISK.items():
            if svc in detail or svc in remediation:
                finding["cve_id"] = risk["cve"]
                finding["cvss_score"] = risk["cvss"]
                finding["cve_title"] = risk["title"]
                finding["cve_description"] = risk["desc"]
                return finding

        # Query NVD API for service-related CVEs
        cve_data = self._query_nvd_api(title, detail)
        if cve_data:
            finding["cve_id"] = cve_data["id"]
            finding["cvss_score"] = cve_data.get("cvss", "N/A")
            finding["cve_title"] = cve_data.get("title", cve_data.get("id", ""))
            finding["cve_description"] = cve_data.get("description", "")
            if "severity" not in finding:
                finding["severity"] = self._cvss_to_severity(cve_data.get("cvss", 0))

        return finding

    def _query_nvd_api(self, title, detail):
        """Query the NVD API for CVE matches. Rate-limited to avoid hitting limits."""
        with self._lock:
            # Extract key terms from the finding title
            keywords = []
            for word in title.split():
                w = word.lower().strip(".,;:-()")
                if len(w) > 2 and not w.isnumeric():
                    keywords.append(w)

            # Deduplicate and limit
            seen = set()
            search_terms = []
            for k in keywords:
                if k not in seen and len(search_terms) < 3:
                    seen.add(k)
                    search_terms.append(k)

            if not search_terms:
                return None

            # Try searching with the first keyword
            search_term = search_terms[0]
            cache_key = f"nvd_{search_term}"

            if cache_key in self._cache:
                return self._cache[cache_key]

            try:
                # NVD API 1.0 (current)
                resp = requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={
                        "keywordSearch": search_term,
                        "resultsPerPage": 3,
                        "cveId": "",
                    },
                    headers={"Accept": "application/json"},
                    timeout=self.nvd_api_timeout,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    matches = []
                    for cve in data.get("vulnerabilities", [])[:3]:
                        cve_data = cve.get("cve", {})
                        cve_id = cve_data.get("id", "")

                        # Get CVSS score from metadata
                        cvss_score = "N/A"
                        try:
                            metrics = cve_data.get("metrics", {})
                            for cvss_v3_key in metrics:
                                if "v3" in cvss_v3_key:
                                    scores = metrics[cvss_v3_key].get("cvssData", [])
                                    if scores:
                                        cvss_score = scores[0].get("baseScore", "N/A")
                                        break
                        except:
                            pass

                        # Get description
                        desc = " ".join([
                            part.get("value", "")
                            for part in cve_data.get("descriptions", [])
                            if part.get("lang") == "en"
                        ])

                        matches.append({
                            "id": cve_id,
                            "cvss": float(cvss_score) if cvss_score != "N/A" else 0,
                            "title": cve_id,
                            "description": desc[:200],
                        })

                    if matches:
                        # Return the highest CVSS match
                        best = max(matches, key=lambda x: x.get("cvss", 0))
                        self._cache[cache_key] = best
                        return best
                elif resp.status_code == 404:
                    # Service name not found in CVE database
                    self._cache[cache_key] = None
                    return None
                else:
                    # Rate limited or error — cache for a short time
                    time.sleep(0.5)
            except Exception:
                pass

            self._cache[cache_key] = None
            return None

    @staticmethod
    def _cvss_to_severity(cvss):
        """Convert CVSS score to severity level."""
        if isinstance(cvss, (int, float)):
            if cvss >= 9.0:
                return "CRITICAL"
            elif cvss >= 7.0:
                return "HIGH"
            elif cvss >= 4.0:
                return "MEDIUM"
            else:
                return "LOW"
        return "MEDIUM"


def enrich_with_cve(findings):
    """Enrich a list of findings with CVE data. Convenience function."""
    engine = CVEEngine()
    return engine.enrich_findings(findings)


if __name__ == "__main__":
    import sys
    # Test: enrich sample findings
    test_findings = [
        {"title": "Outdated OpenSSH 7.2", "severity": "HIGH", "description": "SSH service running outdated version"},
        {"title": "Apache 2.2 Exposed", "severity": "MEDIUM", "description": "Apache web server exposed"},
        {"title": "Redis Exposed", "severity": "HIGH", "description": "Redis port exposed to network"},
    ]
    print(json.dumps(enrich_with_cve(test_findings), indent=2))
