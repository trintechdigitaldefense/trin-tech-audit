# TrinTech Digital Defense — Web Vulnerability Scanner
# Detects web app vulnerabilities: headers, tech fingerprinting, info disclosure, SQLi/XSS probes

import json
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


# Known technologies
TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-login", "wp-includes", "wp-json"],
    "Joomla": ["administrator", "Joomla", "com_content"],
    "Drupal": ["sites/default", "drupal", "sites/all"],
    "Apache": ["Apache", "Server: Apache"],
    "Nginx": ["nginx", "Server: nginx"],
    "IIS": ["Microsoft-IIS", "X-Powered-By: ASP.NET"],
    "PHP": ["X-Powered-By: PHP", ".php", "phpinfo"],
    "Tomcat": ["Apache-Coyote", "tomcat"],
    "Django": ["csrfmiddlewaretoken", "Django"],
    "Laravel": ["laravel_session", "X-Powered-By: PHP"],
    "Rails": ["_rails_session", "actionpack"],
    "Express": ["X-Powered-By: Express"],
    "Cloudflare": ["CF-Ray", "cloudflare", "cf-cache-status"],
    "jQuery": ["jquery"],
    "React": ["react", "__NEXT_DATA__", "react-dom"],
    "Vue": ["__vue__", "nuxt"],
    "Next.js": ["_next/static", "next.js"],
    "Bootstrap": ["bootstrap", "bootstrap.css"],
    "ASP.NET": ["ASP.NET", ".aspx"],
    "Go": ["Gin", "Echo Framework", "Gorilla"],
    "Ruby": ["Puma", "Thin", "Unicorn"],
}

# Missing security headers
MISSING_HDRS = {
    "Strict-Transport-Security": ("HSTS missing", "Add: Strict-Transport-Security max-age=31536000; includeSubDomains"),
    "X-Frame-Options": ("Clickjacking risk", "Add: X-Frame-Options DENY"),
    "X-Content-Type-Options": ("MIME sniffing risk", "Add: X-Content-Type-Options nosniff"),
    "Content-Security-Policy": ("CSP missing", "Add: Content-Security-Policy policy"),
    "X-XSS-Protection": ("XSS header missing", "Add: X-XSS-Protection 1; mode=block"),
    "Referrer-Policy": ("Referrer policy missing", "Add: Referrer-Policy strict-origin-when-cross-origin"),
    "Permissions-Policy": ("Permissions policy missing", "Add: Permissions-Policy camera=(), microphone=()"),
}


class WebScanner:
    """Probe web services for vulnerabilities."""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    ]

    def __init__(self, target, ports=None, timeout=3.0):
        self.target = target
        self.ports = ports or [80, 443, 8080, 8443, 8888, 3000, 5000, 9000]
        self.timeout = timeout
        self.findings = []

    def scan(self):
        if not HAS_REQUESTS:
            return {"error": "requests module not installed"}

        urls = self._discover_urls()

        print(f"\n  {CYAN}*{RESET} Scanning {BOLD}{len(urls)}{RESET} web endpoints...")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._probe, url): url for url in urls}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.findings.append(result)
                    status = f"[{result['status_code']}]"
                    print(f"    {GREEN}>{RESET} {result['url']:<45} {status} {DIM}{result.get('technologies', [])}{RESET}")

        # Analyze all findings together
        analysis = self._analyze_findings()
        return {
            "url_count": len(urls),
            "endpoints": self.findings,
            "security_findings": analysis["findings"],
            "summary": {
                "total_endpoints": len(self.findings),
                "total_findings": len(analysis["findings"]),
                "critical": len([f for f in analysis["findings"] if f["severity"] == "CRITICAL"]),
                "high": len([f for f in analysis["findings"] if f["severity"] == "HIGH"]),
                "medium": len([f for f in analysis["findings"] if f["severity"] == "MEDIUM"]),
                "low": len([f for f in analysis["findings"] if f["severity"] == "LOW"]),
            }
        }

    def _discover_urls(self):
        urls = set()
        active_ports = []
        for port in self.ports:
            try:
                sock = socket.create_connection((self.target, port), timeout=2)
                sock.close()
                active_ports.append(port)
            except:
                pass

        # Only probe HTTP/HTTPS ports for real paths
        http_ports = [p for p in active_ports if p in (80, 443, 8080, 8443)]

        for port in http_ports:
            schemes = ["https", "http"] if port == 443 else ["http", "https"]
            for scheme in schemes:
                base = f"{scheme}://{self.target}:{port}"
                urls.add(base)
                # Only probe common vulnerability paths on the main page
                for path in ["/.env", "/.git/config", "/wp-config.php", "/phpinfo.php",
                             "/.well-known/security.txt", "/server-status", "/actuator/health"]:
                    urls.add(f"{base}{path}")

        return sorted(urls)

    def _probe(self, url):
        try:
            r = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True,
                           headers={"User-Agent": self.USER_AGENTS[0]})

            findings = self._analyze_endpoint(r, url)

            return {
                "url": url,
                "status_code": r.status_code,
                "server": r.headers.get("Server", "Unknown"),
                "technologies": findings["technologies"],
                "missing_headers": findings["missing_headers"],
                "info_disclosure": findings["info_disclosure"],
                "security_findings": findings["security_findings"],
                "headers": {k: v for k, v in r.headers.items() if k.lower() not in ["set-cookie", "x-powered-by"]},
            }
        except:
            return None

    def _analyze_endpoint(self, response, url):
        text = response.text[:10000].lower()
        headers = response.headers

        tech = self._detect_technologies(text, headers)
        missing_hdrs = self._check_security_headers(headers)
        info_disc = self._check_info_disclosure(headers)
        security = self._check_vulnerabilities(response, text, headers, url)

        return {
            "technologies": tech,
            "missing_headers": missing_hdrs,
            "info_disclosure": info_disc,
            "security_findings": security,
        }

    def _detect_technologies(self, text, headers):
        found = []
        hstr = str(headers).lower()

        for tech, patterns in TECH_SIGNATURES.items():
            if any(p.lower() in text or p.lower() in hstr for p in patterns):
                found.append(tech)
                break

        return list(dict.fromkeys(found))  # Deduplicate while preserving order

    def _check_security_headers(self, headers):
        missing = []
        h_lower = {k.lower(): k for k in headers.keys()}

        for hdr, (risk, fix) in MISSING_HDRS.items():
            if hdr.lower() not in h_lower:
                missing.append({
                    "header": hdr,
                    "risk": risk,
                    "fix": fix,
                    "severity": "MEDIUM" if "XSS" in hdr or "Content-Type" in hdr else "LOW"
                })

        return missing

    def _check_info_disclosure(self, headers):
        issues = []

        server = headers.get("Server", "")
        if server and server not in ("", "unknown"):
            issues.append({"issue": f"Server disclosed: {server}", "severity": "LOW"})

        xpb = headers.get("X-Powered-By", "")
        if xpb:
            issues.append({"issue": f"Technology disclosed: {xpb}", "severity": "LOW"})

        return issues

    def _check_vulnerabilities(self, response, text, headers, url):
        findings = []

        # HTTPS vs HTTP
        if url.startswith("http://"):
            findings.append({
                "severity": "MEDIUM",
                "title": "Unencrypted HTTP",
                "detail": f"Service running on plaintext HTTP: {url}",
                "remediation": "Redirect all traffic to HTTPS using HSTS"
            })

        # Missing security headers
        for mh in self._check_security_headers(response.headers):
            findings.append({
                "severity": mh["severity"],
                "title": f"Missing: {mh['header']}",
                "detail": mh["risk"],
                "remediation": mh["fix"]
            })

        # Common vulnerability paths
        vuln_paths = {
            "/.env": ("Environment file exposed", "HIGH"),
            "/wp-config.php": ("WordPress config exposed", "CRITICAL"),
            "/phpinfo.php": ("PHP info page exposed", "HIGH"),
            "/.git/config": ("Git repository exposed", "CRITICAL"),
            "/backup": ("Backup files accessible", "HIGH"),
            "/debug": ("Debug endpoint exposed", "MEDIUM"),
            "/server-status": ("Apache status exposed", "HIGH"),
            "/actuator": ("Spring Boot actuator exposed", "HIGH"),
            "/swagger": ("API documentation exposed", "MEDIUM"),
        }

        for path, (desc, severity) in vuln_paths.items():
            if response.url.endswith(path) and response.status_code == 200:
                findings.append({
                    "severity": severity,
                    "title": desc,
                    "detail": f"Path is publicly accessible: {response.url}",
                    "remediation": f"Remove or restrict access to {path}"
                })

        # Information disclosure in response
        if "stack trace" in text or "traceback" in text or "internal server error" in text.lower():
            findings.append({
                "severity": "MEDIUM",
                "title": "Error Information Disclosure",
                "detail": "Application leaks error details in response",
                "remediation": "Configure custom error pages that don't leak internals"
            })

        return findings

    def _analyze_findings(self):
        all_findings = []

        for ep in self.findings:
            # Security findings from this endpoint
            for sf in ep.get("security_findings", []):
                all_findings.append(sf)

            # Missing headers (deduplicate)
            seen_headers = set()
            for mh in ep.get("missing_headers", []):
                if mh["header"] not in seen_headers:
                    all_findings.append(mh)
                    seen_headers.add(mh["header"])

            # Info disclosure
            for id_ in ep.get("info_disclosure", []):
                all_findings.append({
                    "severity": "LOW",
                    "title": "Info Disclosure",
                    "detail": id_["issue"],
                    "url": ep["url"]
                })

        return {"findings": all_findings}


def run_web_scan(target):
    """Run web vulnerability scan. Returns structured data."""
    print(f"\n  {CYAN}{BOLD}{'~'*50}{RESET}")
    print(f"  {BOLD}WEB VULNERABILITY SCAN{RESET} — Target: {YELLOW}{target}{RESET}")
    print(f"  {CYAN}{BOLD}{'~'*50}{RESET}\n")

    scanner = WebScanner(target)
    results = scanner.scan()

    s = results.get("summary", {})
    print(f"\n  {GREEN}+{RESET} {BOLD}WEB SCAN COMPLETE{RESET}")
    print(f"    Endpoints: {BOLD}{s.get('total_endpoints', 0)}{RESET} | Findings: {BOLD}{s.get('total_findings', 0)}{RESET}")
    print(f"    Critical: {RED}{s.get('critical', 0)}{RESET} | High: {YELLOW}{s.get('high', 0)}{RESET} | Medium: {CYAN}{s.get('medium', 0)}{RESET} | Low: {DIM}{s.get('low', 0)}{RESET}\n")

    return results


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "trintechdigitaldefense.github.io"
    data = run_web_scan(target)
    print(json.dumps(data, indent=2, default=str))
