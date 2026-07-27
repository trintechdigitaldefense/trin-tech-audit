# TrinTech Digital Defense — Vulnerability Scanner
# Checks discovered services against known vulnerability database

from .recon_engine import PortScanner, SSLChecker

# Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
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

# Known vulnerable software versions (from banner grabs)
VULNERABLE_SOFTWARE = {
    "vsftpd 2.3.4": ("CRITICAL", "vsftpd 2.3.4 BACKDOOR (CVE-2011-2523)", "Replace immediately."),
    "OpenSSH 3.": ("HIGH", "Outdated OpenSSH 3.x", "Update OpenSSH."),
    "OpenSSH 4.": ("HIGH", "Outdated OpenSSH 4.x", "Update OpenSSH."),
    "OpenSSH 5.": ("HIGH", "Outdated OpenSSH 5.x", "Update OpenSSH."),
    "OpenSSH 6.": ("HIGH", "Outdated OpenSSH 6.x", "Update OpenSSH."),
    "OpenSSH 7.0": ("HIGH", "Outdated OpenSSH 7.0", "Update OpenSSH."),
    "OpenSSH 7.1": ("HIGH", "Outdated OpenSSH 7.1", "Update OpenSSH."),
    "OpenSSH 7.2": ("HIGH", "Outdated OpenSSH 7.2", "Update OpenSSH."),
    "Apache 2.0": ("HIGH", "Outdated Apache 2.0", "Update Apache."),
    "Apache 2.2": ("HIGH", "Outdated Apache 2.2", "Update Apache."),
}


class VulnChecker:
    """Check for vulnerabilities across all discovered services."""

    def __init__(self, target, ports_data, services_data, web_data, ssl_data, banner_data):
        self.target = target
        self.ports = ports_data or []
        self.services = services_data or {}
        self.web = web_data or []
        self.ssl = ssl_data or {}
        self.banners = banner_data or {}
        self.findings = []

    def check(self):
        self.check_ports()
        self.check_web()
        self.check_ssl()
        self.check_banners()
        return self.findings

    def _add(self, severity, title, description, port=None, remediation=""):
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description,
            "port": port,
            "remediation": remediation,
        })

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
        banner_data = self.banners
        if isinstance(banner_data, dict):
            for port, banner in banner_data.items():
                b = str(banner).lower()
                for pattern, (severity, title, fix) in VULNERABLE_SOFTWARE.items():
                    if pattern.lower() in b:
                        self._add(severity, title, f"Banner: {str(banner)[:100]}", port, fix)
                        break


def run_vuln_scan(target):
    """Run vulnerability assessment. Returns structured data."""
    print(f"\n  {CYAN}{BOLD}{'~'*50}{RESET}")
    print(f"  {BOLD}VULNERABILITY SCAN{RESET} — Target: {YELLOW}{target}{RESET}")
    print(f"  {CYAN}{BOLD}{'~'*50}{RESET}\n")

    from .recon_engine import run_recon
    from .web_scan import run_web_scan

    # Run recon to get baseline data
    print(f"  {CYAN}*{RESET} Gathering baseline data for vulnerability analysis...")
    recon_data = run_recon(target)

    ports = recon_data.get("modules", {}).get("ports", [])
    banners = recon_data.get("modules", {}).get("banners", {})
    dns_records = recon_data.get("modules", {}).get("dns_records", {})
    ssl_info = recon_data.get("modules", {}).get("ssl", {})

    # Run web scan if web services found
    web_data = {}
    web_ports = [p["port"] for p in ports]
    if any(p in [80, 443, 8080, 8443, 3000, 5000, 9000] for p in web_ports):
        web_data = run_web_scan(target)

    # Check vulnerabilities
    checker = VulnChecker(target, ports, {}, web_data, ssl_info, banners)
    findings = checker.check()

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 9))

    results = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "target": target,
        "total_findings": len(findings),
        "findings": findings,
        "summary": {
            "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "high": len([f for f in findings if f["severity"] == "HIGH"]),
            "medium": len([f for f in findings if f["severity"] == "MEDIUM"]),
            "low": len([f for f in findings if f["severity"] == "LOW"]),
        }
    }

    for f in findings:
        sev = f["severity"]
        color = {"CRITICAL": "\033[91m", "HIGH": "\033[38;5;208m", "MEDIUM": "\033[93m", "LOW": "\033[96m"}.get(sev, "")
        print(f"  {color}[{sev}]{RESET} {f['title']}{' (:' + str(f['port']) + ')' if f.get('port') else ''}")

    print(f"\n  {GREEN}+{RESET} {BOLD}VULN SCAN COMPLETE{RESET}")
    print(f"    Critical: \033[91m{results['summary']['critical']}{RESET} | High: \033[38;5;208m{results['summary']['high']}{RESET} | Medium: \033[93m{results['summary']['medium']}{RESET} | Low: \033[96m{results['summary']['low']}{RESET}\n")

    return results


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "trintechdigitaldefense.github.io"
    data = run_vuln_scan(target)
    print(__import__('json').dumps(data, indent=2, default=str))
