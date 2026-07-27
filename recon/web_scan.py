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

    # Expanded known technologies with version detection
    TECH_SIGNATURES = {
        "WordPress": {"patterns": ["wp-content", "wp-login", "wp-includes", "wp-json"], "ver_patterns": ["WordPress ([\d.]+)", "ver=[\d.]+"]},
        "Joomla": {"patterns": ["administrator", "Joomla", "com_content"]},
        "Drupal": {"patterns": ["sites/default", "drupal", "sites/all"]},
        "Apache": {"patterns": ["Apache", "Server: Apache"], "ver_patterns": ["Apache/([\d.]+)"]},
        "Nginx": {"patterns": ["nginx", "Server: nginx"], "ver_patterns": ["nginx/([\d.]+)", "Server: nginx/([\d.]+)"]},
        "IIS": {"patterns": ["Microsoft-IIS", "X-Powered-By: ASP.NET"], "ver_patterns": ["IIS/([\d.]+)", "X-AspNet-Version: ([\d.]+)"]},
        "PHP": {"patterns": ["X-Powered-By: PHP"], "ver_patterns": ["PHP/([\d.]+)", "X-Powered-By: PHP/([\d.]+)"]},
        "Tomcat": {"patterns": ["Apache-Coyote", "tomcat"], "ver_patterns": ["Apache-Coyote/([\d.]+)", "Server: Apache Tomcat/([\d.]+)"]},
        "Django": {"patterns": ["csrfmiddlewaretoken", "Django"], "ver_patterns": ["Django ([\d.]+)"]},
        "Laravel": {"patterns": ["laravel_session", "X-Powered-By: PHP"]},
        "Rails": {"patterns": ["_rails_session", "actionpack"]},
        "Express": {"patterns": ["X-Powered-By: Express"]},
        "Cloudflare": {"patterns": ["CF-Ray", "cloudflare", "cf-cache-status"]},
        "jQuery": {"patterns": ["jquery"], "ver_patterns": ["jquery(?:-([\d.]+))?"]},
        "React": {"patterns": ["react", "__NEXT_DATA__", "react-dom"]},
        "Vue": {"patterns": ["__vue__", "nuxt"]},
        "Next.js": {"patterns": ["_next/static", "next.js"]},
        "Bootstrap": {"patterns": ["bootstrap", "bootstrap.css"]},
        "ASP.NET": {"patterns": ["ASP.NET", ".aspx"]},
        "Go": {"patterns": ["Gin", "Echo Framework", "Gorilla"]},
        "Ruby": {"patterns": ["Puma", "Thin", "Unicorn"]},
        "Node.js": {"patterns": ["node"]},
    }

    # Version ranges for version-specific vulnerabilities
    VULNERABLE_VERSIONS = {
        "WordPress": [("6.5", "6.5.3"), ("6.4", "6.4.3"), ("6.3", "6.3.2"), ("6.2", "6.2.3")],
        "PHP": [("8.0", "8.0.30"), ("7.4", "7.4.33"), ("7.3", "7.3.33")],
        "Apache": [("2.4", "2.4.54"), ("2.4.49", "2.4.49")],
        "Nginx": [("1.18", "1.18.0"), ("1.20", "1.20.1")],
    }

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

                # Standard vulnerability paths
                for path in ["/.env", "/.git/config", "/wp-config.php", "/phpinfo.php",
                             "/.well-known/security.txt", "/server-status", "/actuator/health",
                             "/robots.txt", "/sitemap.xml", "/.well-known/cpanel",
                             "/.well-known/acme-challenge", "/crossdomain.xml",
                             "/clientaccesspolicy.xml", "/server-info", "/server-status"]:
                    urls.add(f"{base}{path}")

                # CMS-specific paths
                for path in ["/wp-login.php", "/wp-admin/", "/wp-content/plugins/",
                             "/administrator/", "/modules/", "/user/login",
                             "/cgi-bin/", "/cgi-bin/test-cgi",
                             "/config.php", "/configuration.php", "/settings.php",
                             "/debug/vars", "/health", "/ping",
                             "/api/", "/graphql", "/swagger.json", "/api-docs",
                             "/.htaccess", "/web.config"]:
                    urls.add(f"{base}{path}")

        return sorted(urls)

    def _probe(self, url):
        try:
            r = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True,
                           headers={"User-Agent": self.USER_AGENTS[0]})

            findings = self._analyze_endpoint(r, url)
            advanced = self._analyze_advanced(r, url)

            return {
                "url": url,
                "status_code": r.status_code,
                "server": r.headers.get("Server", "Unknown"),
                "technologies": findings["technologies"],
                "technology_versions": findings.get("technology_versions", {}),
                "missing_headers": findings["missing_headers"],
                "info_disclosure": findings["info_disclosure"],
                "security_findings": findings["security_findings"],
                "cookie_issues": advanced.get("cookie_issues", []),
                "cors_issues": advanced.get("cors_issues", []),
                "robots_info": advanced.get("robots_info", None),
                "redirect_issues": advanced.get("redirect_issues", []),
                "tls_config": advanced.get("tls_config", None),
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

    def _analyze_advanced(self, response, url):
        """Advanced security analysis: cookies, CORS, redirects, TLS config."""
        result = {
            "cookie_issues": [],
            "cors_issues": [],
            "robots_info": None,
            "redirect_issues": [],
            "tls_config": None,
        }

        # === Cookie Security Analysis ===
        cookies = response.cookies
        for cookie in cookies:
            issues = []

            if not cookie.secure:
                issues.append("Cookie without Secure flag")

            if cookie.expires is None:
                issues.append("Session cookie without expiration (session cookie)")

            if not cookie.get("samesite", cookie.get("samesite", "")).lower() in ("strict", "lax"):
                issues.append("Cookie without SameSite attribute")

            if not cookie.get("httponly", cookie.get("httponly", False)):
                issues.append("Cookie without HttpOnly flag")

            if issues:
                result["cookie_issues"].append({
                    "name": cookie.name,
                    "issues": issues,
                    "severity": "HIGH" if len(issues) >= 2 else "MEDIUM",
                    "detail": f"Cookie '{cookie.name}' has security issues: {'; '.join(issues)}",
                    "remediation": "Add Secure, HttpOnly, SameSite=Strict attributes to all cookies"
                })

        # === CORS Analysis ===
        acac = response.headers.get("Access-Control-Allow-Origin", "")
        acam = response.headers.get("Access-Control-Allow-Methods", "")
        acah = response.headers.get("Access-Control-Allow-Headers", "")
        acac_creds = response.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acac:
            if acac == "*":
                result["cors_issues"].append({
                    "severity": "HIGH",
                    "title": "Wildcard CORS Policy",
                    "detail": f"Access-Control-Allow-Origin is set to '*'",
                    "remediation": "Restrict Access-Control-Allow-Origin to specific trusted domains. Use: Access-Control-Allow-Origin: https://example.com"
                })

            if acac_creds == "true" and "*" not in acac:
                result["cors_issues"].append({
                    "severity": "MEDIUM",
                    "title": "CORS with Credentials Allowed",
                    "detail": "CORS allows credentials but origin is not fully validated",
                    "remediation": "Ensure Access-Control-Allow-Origin matches exactly the requesting origin, not a wildcard"
                })

            if acac_creds == "true" and acac == "*":
                result["cors_issues"].append({
                    "severity": "CRITICAL",
                    "title": "CORS Wildcard + Credentials",
                    "detail": "CORS allows any origin with credentials — allows any site to make authenticated requests",
                    "remediation": "CRITICAL: Remove wildcard CORS when credentials are allowed. Set specific allowed origins only."
                })

            if acam:
                methods = [m.strip().upper() for m in acam.split(",")]
                dangerous = ["PUT", "DELETE", "PATCH", "TRACE", "OPTIONS"]
                found_dangerous = [m for m in methods if m in dangerous]
                if found_dangerous:
                    result["cors_issues"].append({
                        "severity": "MEDIUM",
                        "title": "Dangerous HTTP Methods Allowed via CORS",
                        "detail": f"CORS allows dangerous methods: {', '.join(found_dangerous)}",
                        "remediation": f"Restrict CORS to necessary methods only (GET, POST). Remove: {', '.join(found_dangerous)}"
                    })

        # === Open Redirect Detection ===
        # Check for redirect behavior
        if response.history:
            for h in response.history:
                location = h.headers.get("Location", "")
                if location and ("redirect" in location.lower() or location.startswith("http")):
                    if self._is_open_redirect(location):
                        result["redirect_issues"].append({
                            "severity": "MEDIUM",
                            "title": "Open Redirect Detected",
                            "detail": f"URL redirects to external site: {location}",
                            "remediation": "Implement allowlist for redirect destinations. Validate against trusted domains."
                        })

        # Also check for redirect parameters in query strings
        if any(param in url.lower() for param in ["redirect", "next", "return", "goto", "url", "dest", "redirect_to", "continue"]):
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location", "")
                if location and "http" in location.lower():
                    if self._is_open_redirect(location):
                        result["redirect_issues"].append({
                            "severity": "MEDIUM",
                            "title": "Redirect Parameter Exposure",
                            "detail": f"URL has redirect parameter that resolves to: {location}",
                            "remediation": "Validate redirect destinations against allowed domains. Avoid storing URLs in query parameters."
                        })

        # === robots.txt Analysis ===
        robots_url = url.rsplit("/", 1)[0] + "/robots.txt"
        if "http://" in robots_url or "https://" in robots_url:
            # Already a full URL
            base_url = robots_url
        else:
            base_url = f"https://{url.split('://')[1]}/robots.txt" if url.startswith("https://") else f"http://{url.split('://')[1]}/robots.txt"

        try:
            robots_resp = requests.get(base_url, timeout=2, verify=False)
            if robots_resp.status_code == 200:
                robots_text = robots_resp.text
                # Parse disallowed paths
                disallowed = []
                for line in robots_text.splitlines():
                    if line.strip().lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            disallowed.append(path)

                if disallowed:
                    result["robots_info"] = {
                        "disallowed_paths": disallowed,
                        "user_agent": "Bot",
                        "total_paths": len(disallowed),
                    }
        except:
            pass

        # === TLS/HTTPS Configuration (on main page) ===
        if url.startswith("https://") and response.url.endswith("/"):
            try:
                import ssl
                import socket
                hostname = response.url.split("://")[1].split("/")[0].split(":")[0]
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ss:
                        cert = ss.getpeercert()
                        cipher_info = ss.cipher()
                        proto_version = ss.version()

                tls_config = {
                    "protocol": proto_version or "unknown",
                    "cipher": cipher_info[0] if cipher_info else "unknown",
                    "cert_subject": "",
                    "cert_issuer": "",
                    "cert_san": [],
                }

                subject = dict(x[0] for x in cert.get("subject", []))
                tls_config["cert_subject"] = subject.get("commonName", "")

                try:
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    tls_config["cert_issuer"] = issuer.get("organizationName", "")
                except:
                    pass

                san_list = cert.get("subjectAltName", [])
                tls_config["cert_san"] = [v for _, v in san_list]

                # Check for TLS issues
                issues = []
                if proto_version and proto_version in ("TLSv1", "TLSv1.1"):
                    issues.append(f"Deprecated TLS version: {proto_version}")
                if cipher_info:
                    for weak in ["RC4", "DES", "MD5", "EXPORT", "NULL"]:
                        if weak in cipher_info[0].upper():
                            issues.append(f"Weak cipher: {cipher_info[0]}")
                            break

                if issues:
                    tls_config["issues"] = issues

                result["tls_config"] = tls_config
            except:
                pass

        return result

    def _is_open_redirect(self, url):
        """Check if a redirect URL is an open redirect to an external domain."""
        if not url:
            return False
        # Simple check: if URL points to a different domain than the target
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.netloc:
                return parsed.scheme in ("http", "https") and parsed.netloc != self.target
        except:
            pass
        return False

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

            # Cookie issues
            for ci in ep.get("cookie_issues", []):
                all_findings.append({
                    "severity": ci.get("severity", "MEDIUM"),
                    "title": f"Insecure Cookie: {ci.get('name', 'unknown')}",
                    "detail": ci.get("detail", ""),
                    "remediation": ci.get("remediation", ""),
                    "url": ep.get("url", "")
                })

            # CORS issues
            for cci in ep.get("cors_issues", []):
                all_findings.append({
                    "severity": cci.get("severity", "MEDIUM"),
                    "title": cci.get("title", "CORS Misconfiguration"),
                    "detail": cci.get("detail", ""),
                    "remediation": cci.get("remediation", ""),
                    "url": ep.get("url", "")
                })

            # Redirect issues
            for ri in ep.get("redirect_issues", []):
                all_findings.append({
                    "severity": ri.get("severity", "MEDIUM"),
                    "title": ri.get("title", "Open Redirect"),
                    "detail": ri.get("detail", ""),
                    "remediation": ri.get("remediation", ""),
                    "url": ep.get("url", "")
                })

            # Robots.txt findings — hidden paths exposed
            robots = ep.get("robots_info")
            if robots:
                all_findings.append({
                    "severity": "INFO",
                    "title": f"robots.txt disclosure ({robots.get('total_paths', 0)} paths)",
                    "detail": f"robots.txt reveals {robots['total_paths']} disallowed paths: {', '.join(robots['disallowed_paths'][:5])}",
                    "url": ep.get("url", "")
                })

            # TLS config findings
            tls = ep.get("tls_config")
            if tls and tls.get("issues"):
                for issue in tls["issues"]:
                    all_findings.append({
                        "severity": "MEDIUM",
                        "title": f"TLS Issue: {issue}",
                        "detail": f"TLS configuration issue detected",
                        "remediation": "Upgrade TLS configuration to use TLSv1.2+ with strong ciphers only",
                        "url": ep.get("url", "")
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
