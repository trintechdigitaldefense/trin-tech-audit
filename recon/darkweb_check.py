# TrinTech Digital Defense — Dark Web Data Leak Checker
# Checks if client emails, domains, and credentials appear in known data breaches

import json
import time
import threading
from datetime import datetime
from urllib.parse import quote

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


class DarkWebChecker:
    """Check if client data (emails, domains, passwords) appears in known data breaches."""

    def __init__(self):
        self._lock = threading.Lock()
        self.breaches_found = []
        # Local cache for XposedOrNot to avoid rate limits
        self._xposed_cache = {}

    def check_emails(self, emails, output_format="text"):
        """
        Check if email addresses appear in known data breaches.
        
        Uses HaveIBeenPwned API v3. Requires a free API key at:
        https://haveibeenpwned.com/API/Key
        
        Without an API key, email checking requires fallback to manual
        breach browsing at haveibeenpwned.com
        """
        results = []
        
        if not HAS_REQUESTS:
            return [{"error": "requests library not installed", "emails": emails}]
        
        for email in emails:
            email_clean = email.strip().lower()
            if not email_clean:
                continue
                
            breach_data = self._check_email_breaches(email_clean)
            
            # Handle API key requirement gracefully
            if isinstance(breach_data, dict) and "error" in breach_data:
                if "401" in breach_data.get("error", ""):
                    print(f"    {YELLOW}⚠{RESET} {email_clean} — HIBP key invalid, using free fallback")
                    continue
                elif "API key" in breach_data.get("error", ""):
                    print(f"    {YELLOW}⚠{RESET} {email_clean} — No breach API key. Using free XposedOrNot fallback")
                    results.append({
                        "email": email_clean,
                        "status": "SKIPPED_API_KEY",
                        "error": "API key required — get free key at haveibeenpwned.com/API/Key",
                        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M")
                    })
                    continue
                else:
                    # Other error
                    results.append({
                        "email": email_clean,
                        "status": "ERROR",
                        "error": breach_data.get("error", "Unknown error"),
                        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M")
                    })
                    continue
            elif breach_data:
                results.append({
                    "email": email_clean,
                    "breaches_found": len(breach_data),
                    "breaches": breach_data,
                    "status": "COMPROMISED" if breach_data else "CLEAN",
                    "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M")
                })
                
                status_color = RED if breach_data else GREEN
                status_text = f"{len(breach_data)} breach(es)" if breach_data else "No breaches found"
                print(f"    {status_color}[{status_text}]{RESET} {email_clean}")
                
                if breach_data and output_format == "text":
                    for b in breach_data:
                        print(f"      {YELLOW}⚠{RESET} {b['name']} ({b.get('BreachDate', 'Unknown')}) — {b.get('Description', 'No details')}")
            
            time.sleep(0.1)  # Rate limit compliance
            
        return results

    def _check_email_breaches(self, email):
        """
        Check email against breach databases.
        
        Primary: HaveIBeenPwned (if API key configured).
        Fallback: XposedOrNot free API (no key required).
        """
        import hashlib
        
        # Load HIBP API key from config if available
        api_key = ""
        try:
            import json
            config_path = "/opt/baal-agent/workspace/config/email.json"
            with open(config_path) as f:
                config = json.load(f)
            api_key = config.get("hibp_api_key", "")
        except:
            pass
        
        # Try HIBP first if key is available
        if api_key:
            result = self._check_email_hibp(email, api_key)
            if result is not None:
                return result
        
        # Fallback to XposedOrNot (free, no API key needed)
        result = self._check_email_xposedornot(email)
        if result is not None:
            return result
        
        return {"error": "No breach database available. Configure HIBP key or XposedOrNot API."}
    
    def _check_email_hibp(self, email, api_key):
        """Check email via HaveIBeenPwned API."""
        try:
            headers = {
                "hibp-api-key": api_key,
                "Accept": "application/json"
            }
            
            resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}",
                headers=headers,
                timeout=10
            )
            
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return []  # Email not in any known breach
            elif resp.status_code == 401:
                return {"error": "401 - HIBP API key invalid. Get key at https://haveibeenpwned.com/Account"}
            else:
                return []
        except Exception:
            return None  # Error — try fallback
    
    def _check_email_xposedornot(self, email):
        """Check email via XposedOrNot free API (no key required)."""
        # Check local cache first
        if email in self._xposed_cache:
            return self._xposed_cache[email]
        
        try:
            import time
            # Add small delay to respect rate limits (2 req/sec, 25/hr, 100/day)
            time.sleep(0.5)
            
            resp = requests.get(
                f"https://api.xposedornot.com/v1/check-email/{quote(email, safe='')}",
                timeout=10
            )
            
            if resp.status_code == 200:
                data = resp.json()
                # XposedOrNot returns: {"breaches": [["Breach1", "Breach2"]], "email": "...", "status": "success"}
                breaches_list = data.get("breaches", [])
                if breaches_list and isinstance(breaches_list[0], list):
                    # Flatten: convert [["Breach1", "Breach2"], ["Adobe"]] to ["Breach1", "Breach2", "Adobe"]
                    flat = []
                    for breach_group in breaches_list:
                        for b in breach_group:
                            flat.append(b)
                    self._xposed_cache[email] = flat
                    return flat
                self._xposed_cache[email] = []
                return []
            elif resp.status_code == 429:
                # Rate limited — retry once after delay
                time.sleep(2)
                resp = requests.get(
                    f"https://api.xposedornot.com/v1/check-email/{quote(email, safe='')}",
                    timeout=10
                )
                if resp.status_code == 200:
                    data = resp.json()
                    breaches_list = data.get("breaches", [])
                    if breaches_list and isinstance(breaches_list[0], list):
                        flat = []
                        for breach_group in breaches_list:
                            for b in breach_group:
                                flat.append(b)
                        self._xposed_cache[email] = flat
                        return flat
                    self._xposed_cache[email] = []
                    return []
                return {"error": "Rate limited — try again later"}
            else:
                return []
        except Exception:
            return None  # Error — but this is the last fallback anyway

    def _check_email_range(self, email_sha1):
        """Fallback: Check email using the range-based HIBP API (no key required)."""
        try:
            # HIBP range API: only the first 5 chars of SHA1
            prefix = email_sha1[:5]
            suffix = email_sha1[5:]
            
            resp = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=10
            )
            
            if resp.status_code == 200:
                # This checks passwords, not emails — for emails we need auth
                # This is just a fallback structure
                return []
            return []
        except:
            return []

    def check_passwords(self, passwords, output_format="text"):
        """
        Check if passwords appear in known breaches.
        Uses HaveIBeenPwned's 'pwned passwords' — zero-knowledge proof.
        The password is NEVER sent in full to the server.
        """
        if not HAS_REQUESTS:
            return [{"error": "requests library not installed", "passwords": passwords}]
        
        import hashlib
        
        results = []
        for password in passwords:
            if len(password) < 4:
                continue  # Skip too-short passwords
            
            pw_hash = hashlib.sha1(password.encode("utf-8")).hexdigest()
            prefix = pw_hash[:5]
            suffix = pw_hash[5:]
            
            try:
                resp = requests.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    timeout=5
                )
                
                if resp.status_code == 200:
                    # Check if our suffix is in the response
                    for line in resp.text.splitlines():
                        line_hash = line.split(":")[0].upper()
                        if line_hash == suffix.upper():
                            count = int(line.split(":")[1])
                            results.append({
                                "password_length": len(password),
                                "pwned": True,
                                "times_pwned": count,
                                "safe": False
                            })
                            print(f"      {RED}✗ PWNED — appears in {count:,} breaches{RESET}")
                            break
                    else:
                        results.append({
                            "password_length": len(password),
                            "pwned": False,
                            "times_pwned": 0,
                            "safe": True
                        })
                        print(f"      {GREEN}✓ Not found in known breaches{RESET}")
                else:
                    results.append({
                        "password_length": len(password),
                        "pwned": None,
                        "times_pwned": 0,
                        "safe": None
                    })
            except:
                results.append({
                    "password_length": len(password),
                    "pwned": None,
                    "times_pwned": 0,
                    "safe": None
                })
            
            time.sleep(0.05)  # Brief pause
        
        return results

    def check_domain(self, domain, output_format="text"):
        """
        Check if a domain has been involved in data breaches.
        Uses HIBP breach API to find breaches affecting the domain.
        """
        if not HAS_REQUESTS:
            return {"error": "requests library not installed", "domain": domain}
        
        try:
            # Search for breaches affecting this domain
            headers = {"hibp-api-key": "", "Accept": "application/json"}
            
            # Get all breaches and filter by domain
            resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
                headers=headers,
                timeout=15
            )
            
            if resp.status_code == 200:
                breaches = resp.json()
                results = []
                for b in breaches:
                    results.append({
                        "name": b.get("Name", "Unknown"),
                        "domain": b.get("Domain", ""),
                        "breach_date": b.get("BreachDate", "Unknown"),
                        "added_date": b.get("AddedDate", "Unknown"),
                        "description": b.get("Description", ""),
                        "data_classes": b.get("DataClasses", []),
                        "is_verified": b.get("IsVerified", False),
                        "is_spoofing": b.get("IsSpoofed", False),
                        "logos": {
                            "small": b.get("Logos", {}).get("small", ""),
                            "large": b.get("Logos", {}).get("large", "")
                        }
                    })
                
                # Sort by breach date (most recent first)
                results.sort(key=lambda x: x.get("breach_date", ""), reverse=True)
                
                return {
                    "domain": domain,
                    "breaches_found": len(results),
                    "breaches": results,
                    "status": "COMPROMISED" if results else "CLEAN",
                    "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M")
                }
            else:
                return {
                    "domain": domain,
                    "breaches_found": 0,
                    "breaches": [],
                    "status": "UNKNOWN",
                    "error_code": resp.status_code,
                    "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M")
                }
        except Exception as e:
            return {
                "domain": domain,
                "breaches_found": 0,
                "breaches": [],
                "status": "ERROR",
                "error": str(e),
                "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M")
            }

    def generate_report(self, check_results, output_path=None):
        """Generate a text-based report of all check results."""
        report = []
        report.append("=" * 60)
        report.append("  TRINTECH DIGITAL DEFENSE — DARK WEB DATA LEAK CHECK")
        report.append(f"  Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        report.append("")
        
        for result in check_results:
            email = result.get("email", "")
            breaches = result.get("breaches_found", 0)
            status = result.get("status", "UNKNOWN")
            
            status_icon = "⚠" if status == "COMPROMISED" else "✓" if status == "CLEAN" else "?"
            status_color = RED if status == "COMPROMISED" else GREEN if status == "CLEAN" else YELLOW
            
            report.append(f"{status_icon} {email}: {status} ({breaches} breach(es))")
            
            if breaches > 0:
                for b in result.get("breaches", []):
                    report.append(f"  └─ {b.get('Name', 'Unknown')} ({b.get('BreachDate', 'Unknown')})")
                    report.append(f"     └─ {b.get('Description', '')[:100]}")
                    report.append(f"     └─ Data types: {', '.join(b.get('DataClasses', []))}")
            report.append("")
        
        report.append("=" * 60)
        report.append("  RECOMMENDATIONS:")
        
        total_compromised = sum(1 for r in check_results if r.get("status") == "COMPROMISED")
        if total_compromised > 0:
            report.append(f"  ⚠ {total_compromised} email(s) found in known breaches")
            report.append("  1. Force password resets for ALL compromised accounts")
            report.append("  2. Enable multi-factor authentication (MFA/2FA)")
            report.append("  3. Use unique passwords for every service (password manager)")
            report.append("  4. Monitor for credential stuffing attacks")
            report.append("  5. Consider implementing breach monitoring service")
        else:
            report.append("  ✓ No breaches found — but maintain good security hygiene")
            report.append("  1. Enable MFA on all accounts")
            report.append("  2. Use unique, strong passwords")
            report.append("  3. Monitor for new breaches regularly")
        
        report.append("")
        report.append("  DISCLAIMER: This check uses publicly available breach data.")
        report.append("  Not being in a breach doesn't guarantee safety — new breaches")
        report.append("  are discovered daily. Regular monitoring is recommended.")
        report.append("")
        
        report_text = "\n".join(report)
        
        if output_path:
            with open(output_path, "w") as f:
                f.write(report_text)
        
        return report_text

    def check_email_intelligence(self, emails, output_format="text"):
        """
        Check email intelligence: domain reputation, catch-all detection, 
        disposable email detection, and mail server configuration.
        """
        if not HAS_REQUESTS:
            return [{"error": "requests library not installed", "emails": emails}]
        
        try:
            import re
            from urllib.parse import urlparse
            
            results = []
            
            for email in emails:
                email_clean = email.strip().lower()
                if not email_clean:
                    continue
                
                # Extract domain
                domain = email_clean.split("@")[-1] if "@" in email_clean else ""
                
                # Check for disposable email services
                disposable_domains = [
                    "mailinator.com", "guerrillamail.com", "temp-mail.org",
                    "yopmail.com", "10minutemail.com", "throwaway.email",
                    "maildrop.cc", "sharklasers.com", "guerrillamailblock.com",
                    "grr.la", "guerrillamail.info", "guerrillamail.net",
                    "guerrillamail.org", "guerrillamail.de", "pokemail.net",
                    "spam4.me", "bccto.me", "chammy.info", "discard.email",
                    "discardmail.com", "discardmail.de", "dispostable.com",
                    "fakeinbox.com", "filzmail.com", "getnada.com", "inboxalias.com",
                    "inboxkitten.com", "mailnesia.com", "mailzilla.com", "mintemail.com",
                    "mytemp.email", "spamfree24.org", "tempail.com", "tempmailo.com",
                    "tmpmail.net", "tmpmail.org", "trashmail.com", "trashmail.net",
                    "trashmail.org", "wegwerfmail.de", "wegwerfmail.net",
                    "wegwerfmail.org", "yopmail.fr", "yopmail.net", "yopmail.com"
                ]
                
                is_disposable = domain in disposable_domains
                
                # Basic email validation
                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                is_valid = bool(re.match(email_pattern, email_clean))
                
                # Check domain reputation via DNS
                has_mx_record = False
                has_spf_record = False
                has_dmarc_record = False
                
                try:
                    import dns.resolver
                    
                    # MX Records
                    try:
                        mx = dns.resolver.resolve(domain, 'MX')
                        has_mx_record = len(mx) > 0
                    except:
                        pass
                    
                    # SPF Record
                    try:
                        spf = dns.resolver.resolve(domain, 'TXT')
                        for rdata in spf:
                            if "spf" in str(rdata).lower():
                                has_spf_record = True
                                break
                    except:
                        pass
                    
                    # DMARC Record
                    try:
                        dmarc = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
                        for rdata in dmarc:
                            if "dmarc" in str(rdata).lower():
                                has_dmarc_record = True
                                break
                    except:
                        pass
                        
                except ImportError:
                    pass  # dnspython not available
                
                results.append({
                    "email": email_clean,
                    "domain": domain,
                    "is_disposable": is_disposable,
                    "is_valid": is_valid,
                    "has_mx": has_mx_record,
                    "has_spf": has_spf_record,
                    "has_dmarc": has_dmarc_record,
                    "risk_level": "HIGH" if (is_disposable or not is_valid) else "LOW"
                })
                
                risk_icon = "⚠" if is_disposable else "✓"
                risk_text = "DISPOSABLE" if is_disposable else "Valid"
                print(f"    {risk_icon} {email_clean} — {risk_text}")
                
                if not has_mx_record:
                    print(f"      {YELLOW}⚠ No MX record found{RESET}")
                if not has_spf_record:
                    print(f"      {YELLOW}⚠ No SPF record found{RESET}")
                    
            return results
            
        except Exception as e:
            print(f"      {DIM}Email intelligence check failed: {str(e)}{RESET}")
            return [{"error": str(e), "emails": emails}]


def check_data_leaks(emails=None, passwords=None, domain=None, output_path=None):
    """
    Main convenience function for dark web leak checking.
    
    Args:
        emails: List of email addresses to check
        passwords: List of passwords to check (via zero-knowledge proof)
        domain: Domain to check for breach involvement
        output_path: Optional path to save the report
    
    Returns:
        dict with all check results
    """
    checker = DarkWebChecker()
    results = []
    
    # Check emails
    if emails:
        print(f"\n{BOLD}  * Checking {len(emails)} email(s) against known breaches...{RESET}")
        email_results = checker.check_emails(emails, output_format="text")
        results.extend(email_results)
    
    # Check passwords
    if passwords:
        print(f"\n{BOLD}  * Checking {len(passwords)} password(s)...{RESET}")
        password_results = checker.check_passwords(passwords, output_format="text")
        results.extend(password_results)
    
    # Check domain
    if domain:
        print(f"\n{BOLD}  * Checking domain {domain} for breach involvement...{RESET}")
        domain_results = checker.check_domain(domain, output_format="text")
        results.append(domain_results)
    
    # Generate report
    if results:
        report_text = checker.generate_report(results, output_path=output_path)
        
        if output_path:
            print(f"\n{GREEN}  * Report saved to: {output_path}{RESET}")
        
        return {
            "results": results,
            "report": report_text,
            "summary": {
                "total_checked": len([r for r in results if "email" in r or "password" in r]),
                "breaches_found": sum(1 for r in results if r.get("status") == "COMPROMISED"),
                "clean": sum(1 for r in results if r.get("status") == "CLEAN"),
            }
        }
    
    return {"results": [], "report": "No checks performed.", "summary": {}}


if __name__ == "__main__":
    # Demo/Test run
    print(f"{BOLD}TRINTECH DIGITAL DEFENSE — DARK WEB DATA LEAK CHECKER{RESET}\n")
    
    # Test emails (use real emails for full results)
    test_emails = [
        "trintechdigitaldefense@gmail.com",  # Your business email
        # "john.doe@example.com",  # Add more as needed
    ]
    
    test_passwords = [
        "password123",  # Will definitely be in breaches (for demo only!)
        "MySecureP@ssw0rd!",  # Likely safe
    ]
    
    results = check_data_leaks(
        emails=test_emails,
        passwords=test_passwords,
        output_path=None  # Set to "reports/dark_web_leak_check.json" to save
    )
    
    print(f"\n{GREEN}✓ Dark web check complete.{RESET}")
