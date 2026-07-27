# TrinTech Digital Defense — Vulnerability Scanner
# Checks discovered services against known vulnerability database
# Enriched with CVE data and version-specific vulnerability matching

import re
import json

# Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# Known vulnerable port configurations
DANGEROUS_PORTS = {
    21: ("MEDIUM", "FTP Open", "FTP sends credentials in cleartext.", "Use SFTP/FTPS instead."),
    23: ("HIGH", "Telnet Open", "All data transmitted in cleartext.", "Replace with SSH."),
    135: ("HIGH", "MSRPC Open", "Commonly exploited (MS03-026).", "Restrict with firewall."),
    139: ("HIGH", "NetBIOS Open", "Exposes shares and system info.", "Disable or restrict to LAN."),
    445: ("HIGH", "SMB Open", "Target for EternalBlue/WannaCry.", "Patch and restrict access."),
    512: ("CRITICAL", "rexec Open", "Remote exec with no strong auth.", "Disable immediately."),
    513: ("CRITICAL", "rlogin Open", "Remote login - weak auth.", "Disable immediately."),
    514: ("CRITICAL", "rsh Open", "Remote shell - no encryption.", "Disable. Use SSH."),
    1433: ("HIGH", "MSSQL Exposed", "Database port exposed to network.", "Restrict to app servers."),
    1521: ("HIGH", "Oracle Exposed", "Database port exposed.", "Restrict access."),
    3306: ("HIGH", "MySQL Exposed", "MySQL exposed to network.", "Bind to localhost."),
    3389: ("HIGH", "RDP Open", "Commonly brute-forced, many CVEs.", "Enable NLA, restrict to VPN."),
    4444: ("CRITICAL", "Metasploit Port", "Default Metasploit listener.", "Investigate immediately."),
    5432: ("HIGH", "PostgreSQL Exposed", "Database port exposed.", "Restrict to app servers."),
    5900: ("HIGH", "VNC Open", "Often has weak/no authentication.", "Enable auth, restrict to VPN."),
    6379: ("CRITICAL", "Redis Exposed", "No auth by default. Full data access.", "Bind to localhost. Add password."),
    9200: ("HIGH", "Elasticsearch Exposed", "No auth by default.", "Enable X-Pack security."),
    11211: ("HIGH", "Memcached Exposed", "No auth, DDoS amplification risk.", "Bind to localhost."),
    27017: ("HIGH", "MongoDB Exposed", "Often misconfigured with no auth.", "Enable auth. Restrict network."),
    2049: ("HIGH", "NFS Open", "Can allow unauthorized file access.", "Restrict NFS exports."),
}

# Version-specific vulnerability database
VERSION_VULNS = {
    "OpenSSH": {
        "3.": {"cve": "CVE-2004-0130", "cvss": 10.0, "severity": "CRITICAL", "title": "OpenSSH Pre-Auth Root Access"},
        "4.": {"cve": "CVE-2010-4478", "cvss": 6.8, "severity": "HIGH", "title": "OpenSSH DNS Cache Poisoning"},
        "5.": {"cve": "CVE-2016-0777", "cvss": 7.5, "severity": "HIGH", "title": "OpenSSH GSSAPI Authentication Bypass"},
        "6.": {"cve": "CVE-2016-0778", "cvss": 5.8, "severity": "HIGH", "title": "OpenSSH Key Re-use Attack"},
        "7.0": {"cve": "CVE-2016-19047", "cvss": 7.8, "severity": "HIGH", "title": "OpenSSH Server Side-Channel"},
        "7.2": {"cve": "CVE-2016-10012", "cvss": 7.5, "severity": "HIGH", "title": "OpenSSH User Enumeration"},
        "7.4": {"cve": "CVE-2017-15906", "cvss": 7.5, "severity": "HIGH", "title": "OpenSSH Authentication Bypass"},
    },
    "Apache": {
        "2.0": {"cve": "CVE-2011-3192", "cvss": 7.5, "severity": "HIGH", "title": "Apache Httpd mod_rewrite DoS"},
        "2.2": {"cve": "CVE-2017-9798", "cvss": 7.5, "severity": "HIGH", "title": "Apache 2.2 Heap Overflow"},
        "2.4.0": {"cve": "CVE-2017-9798", "cvss": 7.5, "severity": "HIGH", "title": "Apache httpd Heap Overflow"},
        "2.4.49": {"cve": "CVE-2021-41773", "cvss": 7.8, "severity": "HIGH", "title": "Apache Path Traversal"},
        "2.4.50": {"cve": "CVE-2021-42013", "cvss": 9.8, "severity": "CRITICAL", "title": "Apache RCE via Path Traversal"},
    },
    "vsftpd": {
        "2.3.4": {"cve": "CVE-2011-2523", "cvss": 10.0, "severity": "CRITICAL", "title": "vsftpd 2.3.4 Backdoor Command Execution"},
    },
    "nginx": {
        "1.18.0": {"cve": "CVE-2021-23017", "cvss": 5.3, "severity": "MEDIUM", "title": "Nginx Advanced Bytecode DoS"},
    },
    "Tomcat": {
        "10.1.0": {"cve": "CVE-2024-27321", "cvss": 9.8, "severity": "CRITICAL", "title": "Apache Tomcat JDBC RCE"},
        "9.0.0": {"cve": "CVE-2020-9484", "cvss": 7.5, "severity": "HIGH", "title": "Apache Tomcat DoS via Thread Exhaustion"},
        "8.5": {"cve": "CVE-2020-1938", "cvss": 9.8, "severity": "CRITICAL", "title": "Apache Tomcat Ghostcat AJP RCE"},
    },
    "PHP": {
        "8.0": {"cve": "CVE-2024-4577", "cvss": 6.1, "severity": "HIGH", "title": "PHP CGI Argument Injection"},
        "7.4": {"cve": "CVE-2024-2961", "cvss": 6.1, "severity": "HIGH", "title": "PHP mb_detect_encoding DoS"},
        "5.6": {"cve": "CVE-2018-1053", "cvss": 9.8, "severity": "CRITICAL", "title": "PHP 5.6 Buffer Overflow"},
    },
    "Node.js": {
        "10": {"cve": "CVE-2020-8184", "cvss": 7.5, "severity": "HIGH", "title": "Node.js Arbitrary Code Execution"},
    },
    "MySQL": {
        "5.5": {"cve": "CVE-2023-22082", "cvss": 6.5, "severity": "HIGH", "title": "MySQL Router Heap Overflow"},
        "5.6": {"cve": "CVE-2023-21977", "cvss": 6.5, "severity": "HIGH", "title": "MySQL Server Vulnerability"},
    },
    "PostgreSQL": {
        "15": {"cve": "CVE-2023-39419", "cvss": 6.5, "severity": "HIGH", "title": "PostgreSQL Denial of Service"},
    },
    "WordPress": {
        "6.5": {"cve": "CVE-2024-3445", "cvss": 9.8, "severity": "CRITICAL", "title": "WordPress Stored XSS via oEmbed"},
    },
    "Redis": {
        "default": {"cve": "CVE-2024-28790", "cvss": 5.5, "severity": "MEDIUM", "title": "Redis Cluster Denial of Service"},
    },
    "MongoDB": {
        "default": {"cve": "CVE-2024-2219", "cvss": 3.7, "severity": "MEDIUM", "title": "MongoDB BSON Denial of Service"},
    },
    "Elasticsearch": {
        "default": {"cve": "CVE-2023-31419", "cvss": 7.8, "severity": "HIGH", "title": "Elasticsearch Deserialization RCE"},
    },
}


class VulnChecker:
    """Check for vulnerabilities across all discovered services."""

    def __init__(self, target, ports_data, services_data, web_data, ssl_data, banner_data, version_data=None):
        self.target = target
        self.ports = ports_data or []
        self.services = services_data or {}
        self.web = web_data or []
        self.ssl = ssl_data or {}
        self.banners = banner_data or {}
        self.versions = version_data or {}  # port_str -> (software, version)
        self.findings = []

    def check(self):
        self.check_ports()
        self.check_web()
        self.check_ssl()
        self.check_banners()
        self.check_versions()
        self.check_insecure_configs()
        return self.findings

    def _add(self, severity, title, description, port=None, remediation="", cve_id=None, cvss=None):
        finding = {
            "severity": severity,
            "title": title,
            "description": description,
            "remediation": remediation,
        }
        if port is not None:
            finding["port"] = port
        if cve_id:
            finding["cve_id"] = cve_id
        if cvss:
            finding["cvss_score"] = cvss
        self.findings.append(finding)

    def check_ports(self):
        for p in self.ports:
            port_num = p["port"] if isinstance(p, dict) else p
            if isinstance(port_num, int) and port_num in DANGEROUS_PORTS:
                sev, title, desc, fix = DANGEROUS_PORTS[port_num]
                self._add(sev, title, desc, port_num, fix)

    def check_web(self):
        web_data = self.web
        if isinstance(web_data, dict):
            web_data = web_data.get("endpoints", web_data.get("url_endpoints", []))

        for svc in web_data:
            if not isinstance(svc, dict):
                continue

            url = svc.get("url", "")
            findings = svc.get("security_findings", [])

            for f in findings:
                self._add(
                    f.get("severity", "MEDIUM"),
                    f.get("title", "Web vulnerability"),
                    f.get("detail", "Web service vulnerability"),
                    remediation=f.get("remediation", "Review and fix")
                )

            missing = svc.get("missing_headers", [])
            for mh in missing:
                if isinstance(mh, dict) and "header" in mh:
                    self._add(
                        mh.get("severity", "LOW"),
                        f"Missing: {mh['header']}",
                        mh.get("risk", "Security header missing"),
                        remediation=mh.get("fix", "Add security header")
                    )

            # Cookie issues from advanced scan
            for ci in svc.get("cookie_issues", []):
                self._add(
                    ci.get("severity", "MEDIUM"),
                    f"Insecure Cookie: {ci.get('name', 'unknown')}",
                    ci.get("detail", ""),
                    remediation=ci.get("remediation", "Fix cookie attributes")
                )

            # CORS issues from advanced scan
            for cci in svc.get("cors_issues", []):
                self._add(
                    cci.get("severity", "MEDIUM"),
                    cci.get("title", "CORS Misconfiguration"),
                    cci.get("detail", ""),
                    remediation=cci.get("remediation", "Fix CORS policy")
                )

            if url.startswith("http://"):
                self._add("MEDIUM", "Unencrypted HTTP", f"Service on plaintext HTTP: {url}", remediation="Redirect all traffic to HTTPS")

    def check_ssl(self):
        ssl_data = self.ssl
        if isinstance(ssl_data, dict):
            issues = ssl_data.get("issues", [])
            for issue in issues:
                if issue.get("severity") in ("CRITICAL", "HIGH", "MEDIUM"):
                    self._add(
                        issue["severity"],
                        f"SSL/TLS: {issue['msg']}",
                        "SSL/TLS misconfiguration",
                        443,
                        "Review SSL/TLS configuration"
                    )

    def check_banners(self):
        for port, banner in self.banners.items():
            b = str(banner).lower()
            # Check old VULNERABLE_SOFTWARE patterns
            VULNERABLE_SOFTWARE = {
                "vsftpd 2.3.4": ("CRITICAL", "vsftpd 2.3.4 BACKDOOR (CVE-2011-2523)", "Replace immediately."),
                "OpenSSH 3.": ("HIGH", "Outdated OpenSSH 3.x", "Update OpenSSH."),
                "OpenSSH 4.": ("HIGH", "Outdated OpenSSH 4.x", "Update OpenSSH."),
                "OpenSSH 5.": ("HIGH", "Outdated OpenSSH 5.x", "Update OpenSSH."),
                "OpenSSH 6.": ("HIGH", "Outdated OpenSSH 6.x", "Update OpenSSH."),
                "OpenSSH 7.0": ("HIGH", "Outdated OpenSSH 7.0", "Update OpenSSH."),
                "OpenSSH 7.2": ("HIGH", "Outdated OpenSSH 7.2", "Update OpenSSH."),
                "Apache 2.0": ("HIGH", "Outdated Apache 2.0", "Update Apache."),
                "Apache 2.2": ("HIGH", "Outdated Apache 2.2", "Update Apache."),
            }
            for pattern, (severity, title, fix) in VULNERABLE_SOFTWARE.items():
                if pattern.lower() in b:
                    self._add(severity, title, f"Banner: {str(banner)[:100]}", port, fix)
                    break

    def check_versions(self):
        """Check discovered software versions against known vulnerabilities."""
        for port_str, ver_tuple in self.versions.items():
            software, version = ver_tuple
            try:
                port_num = int(port_str)
            except (ValueError, TypeError):
                continue

            vuln_match = self._match_version_vuln(software, version)
            if vuln_match:
                self._add(
                    vuln_match["severity"],
                    vuln_match["title"],
                    f"{software} version {version} on port {port_num}",
                    port_num,
                    f"Update {software} to latest stable version",
                    cve_id=vuln_match["cve"],
                    cvss=vuln_match["cvss"],
                )

        # Also check banners for version info
        for port, banner in self.banners.items():
            b = str(banner)
            for software in VERSION_VULNS:
                if software.lower() in b.lower():
                    ver_match = re.search(r'[/\s]([\d.]+(?:[-._\d]*\d)?)', b)
                    version = ver_match.group(1) if ver_match else "unknown"
                    vuln = self._match_version_vuln(software, version)
                    if vuln:
                        # Avoid duplicates if already found via versions dict
                        already = any(
                            f.get("port") == int(port) and f.get("cve_id") == vuln["cve"]
                            for f in self.findings
                        )
                        if not already:
                            self._add(
                                vuln["severity"],
                                vuln["title"],
                                f"{software} detected in banner on port {port}: {b[:60]}",
                                int(port),
                                f"Update {software} to latest stable version",
                                cve_id=vuln["cve"],
                                cvss=vuln["cvss"],
                            )

    def check_insecure_configs(self):
        """Check for insecure default configurations on common services."""
        port_set = {p["port"] if isinstance(p, dict) else p for p in self.ports}
        # Use string keys for version data
        version_keys = {str(k) for k in self.versions.keys()}

        unauth_checks = {
            6379: ("Redis", "No authentication by default — full data access",
                   "Bind to localhost (bind 127.0.0.1) and require password (requirepass)"),
            9200: ("Elasticsearch", "No authentication by default — full data access",
                   "Enable X-Pack security in elasticsearch.yml"),
            27017: ("MongoDB", "Often misconfigured with no authentication",
                   "Enable authentication (security.authorization: enabled)"),
            11211: ("Memcached", "No authentication, DDoS amplification risk",
                   "Bind to localhost and disable UDP (disable-udp true)"),
            5900: ("VNC", "Often has weak or no authentication",
                   "Require strong password, restrict to VPN access"),
        }

        for port, (svc, desc, fix) in unauth_checks.items():
            if port in port_set:
                port_str = str(port)
                if port_str not in version_keys:
                    self._add(
                        "MEDIUM",
                        f"{svc} May Be Unauthenticated",
                        f"{svc} on port {port} — {desc}",
                        port, fix
                    )

    def _match_version_vuln(self, software, version):
        """Match a software+version against the version-specific vulnerability database."""
        if software not in VERSION_VULNS:
            return None

        vulns = VERSION_VULNS[software]

        if "default" in vulns:
            return vulns["default"]

        if version == "unknown" or version == "":
            return None

        matched = None
        for vuln_ver, vuln_data in vulns.items():
            if version.startswith(vuln_ver) or version == vuln_ver:
                matched = vuln_data
                break

        return matched


def run_vuln_scan(target, recon_data=None, web_data=None):
    """Run vulnerability assessment. Returns structured data."""
    print(f"\n  {CYAN}{BOLD}{'~'*50}{RESET}")
    print(f"  {BOLD}VULNERABILITY SCAN{RESET} — Target: {YELLOW}{target}{RESET}")
    print(f"  {CYAN}{BOLD}{'~'*50}{RESET}\n")

    from .recon_engine import run_recon
    from .web_scan import run_web_scan

    # Use provided data or run fresh
    if recon_data is None:
        print(f"  {CYAN}*{RESET} Gathering baseline data for vulnerability analysis...")
        recon_data = run_recon(target)

    if web_data is None:
        ports = recon_data.get("modules", {}).get("ports", [])
        if any(p["port"] in [80, 443, 8080, 8443, 3000, 5000, 9000] for p in ports):
            web_data = run_web_scan(target)

    ports = recon_data.get("modules", {}).get("ports", [])
    banners = recon_data.get("modules", {}).get("banners", {})
    versions = recon_data.get("modules", {}).get("versions", {})
    ssl_info = recon_data.get("modules", {}).get("ssl", {})

    checker = VulnChecker(target, ports, {}, web_data, ssl_info, banners, versions)
    findings = checker.check()

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 9))

    summary = {
        "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
        "high": len([f for f in findings if f["severity"] == "HIGH"]),
        "medium": len([f for f in findings if f["severity"] == "MEDIUM"]),
        "low": len([f for f in findings if f["severity"] == "LOW"]),
    }

    results = {
        "findings": findings,
        "summary": summary,
    }

    for f in findings:
        sev = f["severity"]
        color = {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": CYAN, "LOW": DIM}.get(sev, RESET)
        port_str = f" (:{f['port']})" if f.get("port") else ""
        cve_str = f" [{f.get('cve_id', '')}]" if f.get("cve_id") else ""
        print(f"  {color}[{sev}]{RESET} {f['title']}{port_str}{cve_str}")

    print(f"\n  {GREEN}+{RESET} {BOLD}VULN SCAN COMPLETE{RESET}")
    print(f"    Critical: {RED}{summary['critical']}{RESET} | High: {YELLOW}{summary['high']}{RESET} | Medium: {CYAN}{summary['medium']}{RESET} | Low: {DIM}{summary['low']}{RESET}\n")

    return results


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "trintechdigitaldefense.github.io"
    data = run_vuln_scan(target)
    print(json.dumps(data, indent=2, default=str))
