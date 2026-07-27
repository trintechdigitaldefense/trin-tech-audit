# TrinTech Digital Defense — Reconnaissance Module
# Host discovery, port scanning, service enumeration, DNS, SSL

import json
import os
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


class PortScanner:
    """Fast concurrent port scanner using Python sockets."""

    TOP_PORTS = [
        21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 161, 194, 389,
        443, 445, 465, 512, 513, 514, 587, 636, 993, 995, 1080, 1433, 1521,
        1723, 1883, 3000, 3306, 3389, 3690, 4444, 5000, 5432, 5900, 5985,
        5986, 6379, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 9300, 11211,
        27017, 50000, 50070, 2181, 2049, 137, 138, 88
    ]

    SERVICE_MAP = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
        88: "Kerberos", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
        143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 512: "rexec", 513: "rlogin", 514: "rsh", 587: "SMTP",
        636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
        1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 3000: "Web", 3306: "MySQL",
        3389: "RDP", 3690: "SVN", 4444: "Metasploit", 5000: "Web", 5432: "PostgreSQL",
        5900: "VNC", 5985: "WinRM", 5986: "WinRM-SSL", 6379: "Redis", 8000: "Web",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "Web", 9000: "PHP-FPM",
        9200: "Elasticsearch", 9300: "Elasticsearch", 11211: "Memcached",
        27017: "MongoDB", 50000: "DB2", 50070: "Hadoop", 2181: "Zookeeper",
        2049: "NFS", 137: "NetBIOS", 138: "NetBIOS"
    }

    def __init__(self, target, ports=None, threads=50, timeout=1.0):
        self.target = target
        self.ports = ports or self.TOP_PORTS
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []

    def scan(self):
        print(f"\n  {CYAN}*{RESET} Scanning {BOLD}{len(self.ports)}{RESET} ports on {YELLOW}{self.target}{RESET} ({self.threads} threads)")

        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in self.ports}
            for future in as_completed(futures):
                r = future.result()
                if r:
                    results.append(r)
                    print(f"    {GREEN}>{RESET} Port {CYAN}{r['port']:<6}{RESET} {YELLOW}{r['service']:<14}{RESET}")

        results.sort(key=lambda x: x["port"])
        self.open_ports = results

        print(f"\n  {GREEN}+{RESET} {BOLD}{len(results)}{RESET} open ports found\n")
        return results

    def _scan_port(self, port):
        try:
            sock = socket.create_connection((self.target, port), timeout=self.timeout)
            sock.close()
            return {"port": port, "state": "open", "service": self.SERVICE_MAP.get(port, "unknown")}
        except (socket.timeout, socket.error, ConnectionRefusedError, OSError):
            return None


class ServiceDetector:
    """Greet running services to identify software and versions."""

    PROBES = {
        21: b"USER anonymous\r\n",
        25: b"EHLO recon\r\n",
        53: b"",  # Handled separately
        80: b"HEAD / HTTP/1.0\r\n\r\n",
        110: b"USER anonymous\r\n",
        143: b"LOGOUT\r\n",
        993: b"LOGOUT\r\n",
        995: b"LOGOUT\r\n",
    }

    def __init__(self, target, ports, timeout=3.0):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.banners = {}

    def grab(self):
        print(f"  {CYAN}*{RESET} Grabbing service banners...")

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._grab_port, p): p for p in self.ports}
            for future in as_completed(futures):
                r = future.result()
                if r:
                    self.banners[r["port"]] = r["banner"]

        for port, banner in self.banners.items():
            print(f"    {GREEN}>{RESET} :{port:<6} {DIM}{banner[:80]}{RESET}")

        return self.banners

    def _grab_port(self, port):
        try:
            sock = socket.create_connection((self.target, port), timeout=self.timeout)
            probe = self.PROBES.get(port, b"")
            if probe:
                sock.sendall(probe)
            sock.settimeout(self.timeout)
            raw = sock.recv(1024)
            sock.close()
            banner = raw.decode("utf-8", "replace").strip()
            return {"port": port, "banner": banner}
        except:
            return None


class DNSModule:
    """DNS enumeration and record discovery."""

    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose

    def enumerate(self):
        print(f"  {CYAN}*{RESET} Performing DNS enumeration...")
        records = {}
        types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5

            for rtype in types:
                try:
                    answers = resolver.resolve(self.target, rtype)
                    recs = [str(r) for r in answers]
                    if recs:
                        records[rtype] = recs
                        if self.verbose:
                            print(f"    {GREEN}>{RESET} {rtype}: {recs[0][:80]}")
                except:
                    pass
        except ImportError:
            # Fallback to dig
            for rtype in types:
                try:
                    r = subprocess.run(
                        ["dig", f"+short", rtype, self.target],
                        capture_output=True, text=True, timeout=5
                    )
                    if r.returncode == 0 and r.stdout.strip():
                        records[rtype] = r.stdout.strip().split("\n")[:5]
                except:
                    pass

        print(f"  {GREEN}+{RESET} {BOLD}{sum(len(v) for v in records.values())}{RESET} DNS records found\n")
        return records

    def subdomain_enum(self, count=50):
        """Simple subdomain enumeration using common names."""
        print(f"  {CYAN}*{RESET} Enumerating subdomains (top {count})...")
        subs = [
            "www", "mail", "ftp", "ssh", "vpn", "admin", "api", "dev", "test",
            "staging", "blog", "shop", "portal", "login", "auth", "m", "static",
            "cdn", "app", "docs", "wiki", "git", "dashboard", "status",
            "support", "help", "remote", "webmail", "ns1", "ns2", "smtp",
            "pop", "imap", "mysql", "redis", "mongo", "db", "backup", "monitor"
        ][:count]

        results = []
        for sub in subs:
            fqdn = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(fqdn)
                results.append({"subdomain": fqdn, "ip": ip})
                print(f"    {GREEN}>{RESET} {fqdn} -> {CYAN}{ip}{RESET}")
            except:
                pass

        print(f"  {GREEN}+{RESET} {BOLD}{len(results)}{RESET} subdomains found\n")
        return results


class SSLChecker:
    """SSL/TLS certificate and protocol analysis."""

    def __init__(self, target, port=443, timeout=5.0):
        self.target = target
        self.port = port
        self.timeout = timeout

    def analyze(self):
        print(f"  {CYAN}*{RESET} Checking SSL/TLS on port {self.port}...")
        result = {
            "target": self.target, "port": self.port,
            "cert": {}, "protocol": None, "cipher": None,
            "issues": [], "grade": "N/A"
        }

        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ss:
                    cert = ss.getpeercert()
                    cipher = ss.cipher()
                    proto = ss.version()

            sub = dict(x[0] for x in cert.get("subject", []))
            iss = dict(x[0] for x in cert.get("issuer", []))
            na = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            nb = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            days = (na - datetime.utcnow()).days
            san = [v for _, v in cert.get("subjectAltName", [])]

            result["cert"] = {
                "subject": sub.get("commonName", ""),
                "issuer": iss.get("organizationName", ""),
                "valid_until": cert["notAfter"],
                "days_left": days,
                "san": san,
                "self_signed": sub == iss,
            }
            result["protocol"] = proto
            result["cipher"] = cipher[0] if cipher else None

            # Security checks
            issues = result["issues"]
            if days < 0:
                issues.append({"severity": "CRITICAL", "msg": f"Certificate EXPIRED {abs(days)} days ago"})
            elif days < 30:
                issues.append({"severity": "HIGH", "msg": f"Expires in {days} days"})
            elif days < 90:
                issues.append({"severity": "MEDIUM", "msg": f"Expires in {days} days"})
            if result["cert"]["self_signed"]:
                issues.append({"severity": "MEDIUM", "msg": "Self-signed certificate"})
            if cipher:
                for weak in ["RC4", "DES", "MD5", "EXPORT", "NULL"]:
                    if weak in cipher[0].upper():
                        issues.append({"severity": "HIGH", "msg": f"Weak cipher: {cipher[0]}"})
                        break
            if proto in ("TLSv1", "TLSv1.1"):
                issues.append({"severity": "HIGH", "msg": f"Deprecated TLS version: {proto}"})

            # Grade
            crit = sum(1 for i in issues if i["severity"] == "CRITICAL")
            high = sum(1 for i in issues if i["severity"] == "HIGH")
            result["grade"] = "F" if crit else ("D" if high > 1 else ("C" if high else ("B" if issues else "A")))

            print(f"  {GREEN}+{RESET} SSL Grade: {BOLD}{result['grade']}{RESET}  Protocol: {proto}  Expires: {days}d")
            for issue in issues:
                sev_color = {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": CYAN}.get(issue["severity"], RESET)
                print(f"    {sev_color}[{issue['severity']}]{RESET} {issue['msg']}")

        except Exception as e:
            result["issues"].append({"severity": "INFO", "msg": f"SSL check skipped: {e}"})

        return result


class WhoisModule:
    """WHOIS lookup for domain information."""

    def lookup(self, target):
        print(f"  {CYAN}*{RESET} Performing WHOIS lookup...")
        try:
            r = subprocess.run(["whois", target], capture_output=True, text=True, timeout=15)
            info = {}
            for line in r.stdout.split("\n"):
                for key in ["Registrar", "Created", "Expiry", "Name Server", "Status", "Domain Status", "Registrant"]:
                    if key.lower() in line.lower() and ":" in line:
                        k, _, v = line.partition(":")
                        info[k.strip()] = v.strip()
            print(f"  {GREEN}+{RESET} {BOLD}{len(info)}{RESET} WHOIS fields extracted\n")
            return info
        except:
            return {"error": "WHOIS lookup failed"}


def run_recon(target):
    """Main reconnaissance function. Returns structured data."""
    print(f"\n  {CYAN}{BOLD}{'~'*50}{RESET}")
    print(f"  {BOLD}RECONNAISSANCE MODULE{RESET} — Target: {YELLOW}{target}{RESET}")
    print(f"  {CYAN}{BOLD}{'~'*50}{RESET}\n")

    data = {"timestamp": datetime.now().isoformat(), "target": target, "modules": {}}

    # 1. Resolve target
    print(f"  {CYAN}*{RESET} Resolving target...")
    try:
        ip = socket.gethostbyname(target)
        data["resolved_ip"] = ip
        print(f"  {GREEN}+{RESET} {BOLD}{target}{RESET} => {CYAN}{ip}{RESET}")
    except socket.gaierror:
        ip = target
        data["resolved_ip"] = None
        print(f"  {YELLOW}![RESET] Not a hostname — treating as IP: {ip}\n")

    # 2. Port scan
    scanner = PortScanner(target, threads=50, timeout=1.0)
    ports = scanner.scan()
    data["modules"]["ports"] = ports

    # 3. Service banner grabbing
    banner_module = ServiceDetector(target, [p["port"] for p in ports], timeout=3.0)
    banners = banner_module.grab()
    data["modules"]["banners"] = banners

    # 4. DNS enumeration
    dns_module = DNSModule(target)
    dns_records = dns_module.enumerate()
    data["modules"]["dns_records"] = dns_records

    # 5. Subdomain enumeration
    subdomains = dns_module.subdomain_enum()
    data["modules"]["subdomains"] = subdomains

    # 6. SSL check (if 443 is open or common)
    common_ssl_ports = [443, 8443, 8888, 9443]
    has_ssl = any(p["port"] in common_ssl_ports for p in ports) or any(p["port"] == 443 for p in ports)
    if has_ssl:
        ssl_checker = SSLChecker(target, port=443)
        ssl_info = ssl_checker.analyze()
        data["modules"]["ssl"] = ssl_info

    # 7. WHOIS
    whois_info = WhoisModule().lookup(target)
    if "error" not in whois_info:
        data["modules"]["whois"] = whois_info

    # Summary
    total_findings = len(ports) + len(dns_records) + len(subdomains) + len(banners)
    print(f"\n  {GREEN}+{RESET} {BOLD}RECON COMPLETE{RESET}")
    print(f"    Open ports: {BOLD}{len(ports)}{RESET} | DNS records: {BOLD}{sum(len(v) for v in dns_records.values())}{RESET} | Subdomains: {BOLD}{len(subdomains)}{RESET} | Banners: {BOLD}{len(banners)}{RESET}\n")

    return data


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "trintechdigitaldefense.github.io"
    data = run_recon(target)
    print(json.dumps(data, indent=2, default=str))
