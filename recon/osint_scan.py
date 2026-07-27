# TrinTech Digital Defense — OSINT Module
# Public information gathering: domain info, email footprint, WHOIS, DNS

import json
import os
import socket
import subprocess
from datetime import datetime
from pathlib import Path

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


class DomainInfo:
    """Gather public domain information."""

    def gather(self, domain):
        print(f"  {CYAN}*{RESET} Gathering public domain intelligence...")
        info = {}

        # Basic DNS
        try:
            ip = socket.gethostbyname(domain)
            info["resolved_ip"] = ip
            print(f"    {GREEN}>{RESET} IP: {CYAN}{ip}{RESET}")
        except:
            info["resolved_ip"] = "unresolvable"

        # Reverse DNS (PTR)
        try:
            ptr = socket.getfqdn(ip) if info.get("resolved_ip") else "N/A"
            info["ptr_record"] = ptr
        except:
            info["ptr_record"] = "N/A"

        # MX records
        try:
            r = subprocess.run(["dig", "+short", "MX", domain], capture_output=True, text=True, timeout=5)
            if r.stdout.strip():
                info["mx_records"] = r.stdout.strip().split("\n")
                print(f"    {GREEN}>{RESET} Mail servers found")
        except:
            pass

        # NS records
        try:
            r = subprocess.run(["dig", "+short", "NS", domain], capture_output=True, text=True, timeout=5)
            if r.stdout.strip():
                info["ns_records"] = r.stdout.strip().split("\n")
        except:
            pass

        # TXT records (SPF, DKIM, DMARC)
        try:
            r = subprocess.run(["dig", "+short", "TXT", domain], capture_output=True, text=True, timeout=5)
            txt = r.stdout.strip()
            if txt:
                info["txt_records"] = txt.split("\n")
                # Check for email security
                for line in txt.split("\n"):
                    if "v=spf1" in line:
                        info["has_spf"] = True
                        info["spf_record"] = line
                    if "dmarc" in line.lower():
                        info["has_dmarc"] = True
                        info["dmarc_record"] = line
                    if "DKIM" in line or "google._domainkey" in line.lower():
                        info["has_dkim"] = True
        except:
            pass

        print(f"    {GREEN}+{RESET} Email security: SPF={'YES' if info.get('has_spf') else 'NO'} DKIM={'YES' if info.get('has_dkim') else 'NO'} DMARC={'YES' if info.get('has_dmarc') else 'NO'}\n")
        return info


class WhoisPublic:
    """Public WHOIS lookup using online sources."""

    def lookup(self, domain):
        print(f"  {CYAN}*{RESET} Checking public WHOIS information...")
        info = {}

        # Try whois command first
        try:
            r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
            text = r.stdout

            # Extract key fields
            for key in ["Domain Name", "Registrar", "Registrant Name", "Registrant Organization",
                       "Created Date", "Expiry Date", "Name Server", "Status",
                       "Registration date", "Expiration date", "Registrant email"]:
                for line in text.split("\n"):
                    if line.lower().startswith(key.lower() + ":") or line.lower().startswith(key.lower() + " "):
                        _, _, val = line.partition(":")
                        info[key] = val.strip()

            if info:
                print(f"    {GREEN}>{RESET} Registrar: {info.get('Registrar', 'N/A')}")
                print(f"    {GREEN}>{RESET} Created: {info.get('Created Date', info.get('Registration date', 'N/A'))}")
                print(f"    {GREEN}>{RESET} Expiry: {info.get('Expiry Date', info.get('Expiration date', 'N/A'))}")
        except:
            info["note"] = "WHOIS lookup unavailable"

        return info


class EmailCheck:
    """Check if email addresses exist publicly (breach check simulation)."""

    def check_email(self, email):
        print(f"  {CYAN}*{RESET} Checking email footprint for: {BOLD}{email}{RESET}")
        results = {
            "email": email,
            "domain": email.split("@")[-1] if "@" in email else email,
            "breach_database": "simulation",
            "findings": [],
        }

        if not HAS_REQUESTS:
            results["note"] = "requests module not available — basic check only"
            results["findings"].append({"type": "basic", "status": "domain_exists"})
            return results

        # Check if domain has any known online presence
        domain = results["domain"]

        # Check common breach databases (HaveIBeenPwned API - requires key, so we simulate)
        # In production, this would use the actual HIBP API with an API key
        results["findings"].append({
            "type": "breach_check",
            "note": "HaveIBeenPwned API not configured",
            "recommendation": "Configure HIBP API key for real breach data",
            "status": "simulated",
        })

        # Check if email pattern is discoverable
        results["findings"].append({
            "type": "email_pattern",
            "format": email,
            "publicly_revealed": True,  # If email is on websites, it's discoverable
            "recommendation": "Consider using contact form instead of direct email"
        })

        return results


class SocialMediaRecon:
    """Check domain/brand on social media platforms."""

    def check(self, domain_or_brand):
        print(f"  {CYAN}*{RESET} Scanning social media footprint for: {BOLD}{domain_or_brand}{RESET}")

        platforms = [
            {"name": "Google", "url": f"https://www.google.com/search?q=site:{domain_or_brand}"},
            {"name": "Shodan", "url": f"https://www.shodan.io/search?query={domain_or_brand}"},
            {"name": "Censys", "url": f"https://censys.io/ipv4?q={domain_or_brand}"},
        ]

        results = []
        for platform in platforms:
            results.append({
                "platform": platform["name"],
                "url": platform["url"],
                "note": "Manual check recommended"
            })

        return results


def run_osint_scan(target):
    """Run OSINT scan. Returns structured data."""
    print(f"\n  {CYAN}{BOLD}{'~'*50}{RESET}")
    print(f"  {BOLD}OSINT MODULE{RESET} — Target: {YELLOW}{target}{RESET}")
    print(f"  {CYAN}{BOLD}{'~'*50}{RESET}\n")

    data = {"timestamp": datetime.now().isoformat(), "target": target, "modules": {}}

    # 1. Domain intelligence
    domain_info = DomainInfo().gather(target)
    data["modules"]["domain"] = domain_info

    # 2. WHOIS
    whois = WhoisPublic().lookup(target)
    if "error" not in whois and "note" not in whois:
        data["modules"]["whois"] = whois

    # 3. Email check (if it looks like an email)
    if "@" in target:
        email_results = EmailCheck().check_email(target)
        data["modules"]["email"] = email_results
    else:
        # Check common email patterns for the domain
        common_emails = [f"admin@{target}", f"info@{target}", f"security@{target}"]
        email_results = {}
        for email in common_emails:
            result = EmailCheck().check_email(email)
            email_results[email] = result
        data["modules"]["email"] = email_results

    # 4. Social media
    brand = target.split(".")[0]  # Use brand name, not full domain
    social = SocialMediaRecon().check(brand)
    data["modules"]["social_media"] = social

    print(f"\n  {GREEN}+{RESET} {BOLD}OSINT COMPLETE{RESET}\n")
    return data


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "trintechdigitaldefense.github.io"
    data = run_osint_scan(target)
    print(json.dumps(data, indent=2, default=str))
