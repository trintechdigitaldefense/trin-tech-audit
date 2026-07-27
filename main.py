#!/usr/bin/env python3
"""
TrinTech Digital Defense — Full Network Audit Suite
CLI tool for comprehensive network scanning, mapping, and professional PDF reporting.

Usage:
    python main.py start <client_name> <target> [options]
    python main.py list
    python main.py run <engagement_id> [modules]
    python main.py report <engagement_id>
    python main.py help

Example:
    python main.py start "Acme Corp" 192.168.1.1/24 --service smallbiz
    python main.py start "ABC Retail" example.com --modules recon web osint
    python main.py run ENG-001 --modules recon web vuln
    python main.py report ENG-001
"""

import argparse
import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path

# Project root
PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
REPORT_DIR = PROJECT_ROOT / "reports"
DATA_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
PURPLE = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner():
    print(f"\n{PURPLE}{'='*64}{RESET}")
    print(f"{CYAN}{BOLD}")
    print("  ____  _____ ____ ___  _   _   _____             ")
    print(" |  _ \\| ____/ ___/ _ \\| \\ | | |  ___|  ___ __ _  ")
    print(" | |_) |  _|| |  | | | |  \\| | | |_   / __/ _` | ")
    print(" |  _ <| |__| |__| |_| | |\\  | |  _| | (_| (_| | ")
    print(" |_| \\_\\_____|____\\___/|_| \\_| |_|    \\___\\__, | ")
    print(f"{RESET}")
    print(f"  {PURPLE}{BOLD}FULL NETWORK AUDIT SUITE{RESET}  {DIM}v1.0.0{RESET}")
    print(f"  {YELLOW}TrinTech Digital Defense{RESET} | Jason Junior Ramdharry")
    print(f"{PURPLE}{'='*64}{RESET}\n")


def save_engagement(engagement):
    path = DATA_DIR / "engagements.json"
    engagements = []
    if path.exists():
        with open(path) as f:
            engagements = json.load(f)
    engagements.append(engagement)
    with open(path, "w") as f:
        json.dump(engagements, f, indent=2, default=str)
    return path


def load_engagement(eng_id):
    path = DATA_DIR / "engagements.json"
    if not path.exists():
        return None
    with open(path) as f:
        engagements = json.load(f)
    for e in engagements:
        if e["id"] == eng_id:
            return e
    return None


def save_scan_data(eng_id, module_name, data):
    path = REPORT_DIR / f"{eng_id}_{module_name}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return path


def create_engagement(client_name, target, service="micro", addons=None, device_count=1):
    eng_id = f"ENG-{datetime.now().strftime('%y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    engagement = {
        "id": eng_id,
        "client_name": client_name,
        "target": target,
        "service": service,
        "addons": addons or [],
        "device_count": device_count,
        "created": datetime.now().isoformat(),
        "status": "initialized",
        "modules_run": [],
        "scan_data": {},
        "report_generated": False,
    }
    save_engagement(engagement)
    print(f"\n  {GREEN}✓{RESET} Engagement created: {BOLD}{eng_id}{RESET}")
    print(f"  {DIM}Client:{RESET} {client_name}")
    print(f"  {DIM}Target:{RESET} {target}")
    print(f"  {DIM}Service:{RESET} {service}")
    print(f"  {DIM}Status:{RESET} {YELLOW}initialized{RESET}")
    print(f"\n  Next: {CYAN}python main.py run {eng_id} <modules>{RESET}\n")
    return engagement


def cmd_start(args):
    create_engagement(
        client_name=args.client,
        target=args.target,
        service=args.service,
        addons=args.addons.split(",") if args.addons else [],
        device_count=args.devices,
    )


def cmd_list(args):
    path = DATA_DIR / "engagements.json"
    if not path.exists():
        print(f"  {YELLOW}![RESET] No engagements found.")
        return
    with open(path) as f:
        engagements = json.load(f)
    print(f"\n  {BOLD}Active Engagements:{RESET}\n")
    print(f"  {DIM}{'ID':<22} {'Client':<20} {'Target':<25} {'Status':<12} {'Date'}{RESET}")
    print(f"  {'-'*90}")
    for e in engagements:
        print(f"  {e['id']:<22} {e['client_name']:<20} {e['target']:<25} {e['status']:<12} {e['created'][:10]}")
    print()


def cmd_run(args):
    eng = load_engagement(args.engagement_id)
    if not eng:
        print(f"  {RED}✗{RESET} Engagement not found: {args.engagement_id}")
        return

    modules = args.modules.split(",") if args.modules else ["recon", "web"]
    print(f"\n  {CYAN}*{RESET} Running modules: {BOLD}{', '.join(modules)}{RESET}")

    results = {}
    for mod in modules:
        mod = mod.strip().lower()
        if mod == "recon":
            results["recon"] = _run_recon(eng["target"], eng.get("device_count", 1))
        elif mod == "web":
            results["web"] = _run_web(eng["target"])
        elif mod == "osint":
            results["osint"] = _run_osint(eng["target"])
        elif mod == "vuln":
            results["vuln"] = _run_vuln(eng["target"], recon_data=results.get("recon"), web_data=results.get("web"))
        elif mod == "darkweb":
            results["darkweb"] = _run_darkweb(eng["target"])
        elif mod == "all":
            results["recon"] = _run_recon(eng["target"], eng.get("device_count", 1))
            results["web"] = _run_web(eng["target"])
            results["osint"] = _run_osint(eng["target"])
            results["vuln"] = _run_vuln(eng["target"], recon_data=results.get("recon"), web_data=results.get("web"))
        else:
            print(f"  {YELLOW}![RESET] Unknown module: {mod} (use: recon, web, osint, vuln, all)")
            continue

        # Save module results
        path = save_scan_data(eng["id"], mod, results[mod])
        print(f"  {GREEN}+{RESET} Module {BOLD}{mod}{RESET} complete — saved to {DIM}{path}{RESET}")
        eng["modules_run"].append(mod)
        eng["scan_data"][mod] = results[mod]

    eng["status"] = "scanning_complete"
    # Update in file
    eng_path = DATA_DIR / "engagements.json"
    with open(eng_path) as f:
        all_eng = json.load(f)
    for i, e in enumerate(all_eng):
        if e["id"] == eng["id"]:
            all_eng[i] = eng
            break
    with open(eng_path, "w") as f:
        json.dump(all_eng, f, indent=2, default=str)

    print(f"\n  {GREEN}✓{RESET} All modules complete. Status: {BOLD}scanning_complete{RESET}")
    print(f"\n  {CYAN}*{RESET} Next: {BOLD}python main.py report {eng['id']}  {RESET}")
    print(f"  {CYAN}*{RESET} This will generate a professional PDF report.\n")


def cmd_report(args):
    eng = load_engagement(args.engagement_id)
    if not eng:
        print(f"  {RED}✗{RESET} Engagement not found: {args.engagement_id}")
        return

    print(f"\n  {CYAN}*{RESET} Generating report for: {BOLD}{eng['client_name']} ({eng['id']}){RESET}")

    # Load all scan data
    scan_data = {}
    for mod in eng.get("modules_run", []):
        path = REPORT_DIR / f"{eng['id']}_{mod}.json"
        if path.exists():
            with open(path) as f:
                scan_data[mod] = json.load(f)

    # Generate PDF
    try:
        from pdf_report import generate_report
    except ImportError:
        from .pdf_report import generate_report
    result = generate_report(eng, scan_data)

    if result:
        eng["report_generated"] = True
        eng["status"] = "complete"
        eng_path = DATA_DIR / "engagements.json"
        with open(eng_path) as f:
            all_eng = json.load(f)
        for i, e in enumerate(all_eng):
            if e["id"] == eng["id"]:
                all_eng[i] = eng
                break
        with open(eng_path, "w") as f:
            json.dump(all_eng, f, indent=2, default=str)

        print(f"\n  {GREEN}✓{RESET} Report generated: {BOLD}{result}{RESET}")
        print(f"  {DIM}Location:{RESET} {REPORT_DIR / result}")
        print()
    else:
        print(f"\n  {RED}✗{RESET} Report generation failed.")


# ==================== MODULE IMPLEMENTATIONS ====================

def _run_recon(target, device_count=1):
    try:
        from recon.recon_engine import run_recon
    except ImportError:
        from .recon.recon_engine import run_recon
    print(f"\n  {CYAN}*{RESET} Running reconnaissance on: {BOLD}{target}{RESET}")
    results = run_recon(target)
    return results


def _run_web(target):
    try:
        from recon.web_scan import run_web_scan
    except ImportError:
        from .recon.web_scan import run_web_scan
    print(f"\n  {CYAN}*{RESET} Running web application scan on: {BOLD}{target}{RESET}")
    results = run_web_scan(target)
    return results


def _run_osint(target):
    try:
        from recon.osint_scan import run_osint_scan
    except ImportError:
        from .recon.osint_scan import run_osint_scan
    print(f"\n  {CYAN}*{RESET} Running OSINT on: {BOLD}{target}{RESET}")
    results = run_osint_scan(target)
    return results


def _run_vuln(target, recon_data=None, web_data=None):
    try:
        from recon.vuln_scan import run_vuln_scan
    except ImportError:
        from .recon.vuln_scan import run_vuln_scan
    print(f"\n  {CYAN}*{RESET} Running vulnerability scan on: {BOLD}{target}{RESET}")
    results = run_vuln_scan(target, recon_data=recon_data, web_data=web_data)

    # Enrich findings with CVE data from NVD API
    try:
        from recon.cve_engine import enrich_with_cve
        enriched = enrich_with_cve(results.get("findings", []))
        results["findings"] = enriched
    except Exception:
        pass

    return results


def _run_darkweb(target):
    try:
        from recon.darkweb_check import check_data_leaks
    except ImportError:
        from .recon.darkweb_check import check_data_leaks
    
    print(f"\n  {CYAN}*{RESET} Running dark web leak check on: {BOLD}{target}{RESET}")
    
    results = check_data_leaks(
        domain=target,
        output_path=str(REPORT_DIR / f"darkweb_{target.replace('.', '_')}.txt")
    )
    
    return results


def cmd_darkweb(args):
    """Run dark web data leak check against email(s), domain, or passwords."""
    results = {}
    
    # Check emails from engagement or provided
    emails = args.emails
    if args.email:
        emails = args.email
    
    if not emails and args.engagement_id:
        eng = load_engagement(args.engagement_id)
        if eng:
            # Extract emails from OSINT data if available
            osint_path = REPORT_DIR / f"{args.engagement_id}_osint.json"
            if osint_path.exists():
                with open(osint_path) as f:
                    osint_data = json.load(f)
                emails = osint_data.get("emails", [])
    
    # Check domain from engagement or provided
    domain = args.domain
    if not domain and args.target:
        domain = args.target
    
    # Build check config
    check_args = {}
    if emails:
        check_args["emails"] = [e.strip() for e in emails.split(",")]
    if domain:
        check_args["domain"] = domain
    if args.passwords:
        check_args["passwords"] = [p.strip() for p in args.passwords.split(",")]
    
    if not check_args:
        print(f"  {YELLOW}![RESET] No targets provided.")
        print(f"\n  {CYAN}*{RESET} Usage:")
        print(f"    python main.py darkweb --email user@company.com")
        print(f"    python main.py darkweb --domain company.com")
        print(f"    python main.py darkweb --emails a@b.com,c@d.com --domain company.com")
        print(f"    python main.py darkweb ENG-XXX --emails (from osint data)")
        print(f"    python main.py darkweb --passwords password123,s3cur3P@ss")
        return
    
    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}  TRINTECH DIGITAL DEFENSE — DARK WEB DATA LEAK CHECK{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    
    # Run check
    try:
        from recon.darkweb_check import check_data_leaks
        output_path = str(REPORT_DIR / f"darkweb_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        if args.engagement_id:
            output_path = str(REPORT_DIR / f"darkweb_{args.engagement_id}.txt")
        
        check_result = check_data_leaks(**check_args, output_path=output_path)
        results["check"] = check_result
        
        # Save results with engagement ID for report generation
        if args.engagement_id:
            json_path = str(REPORT_DIR / f"{args.engagement_id}_darkweb.json")
            output_path = str(REPORT_DIR / f"darkweb_{args.engagement_id}.txt")
        else:
            json_path = str(REPORT_DIR / f"darkweb_manual_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        with open(json_path, "w") as f:
            json.dump(check_result, f, indent=2, default=str)
        
        print(f"\n  {GREEN}✓{RESET} Dark web check complete.")
        print(f"  {DIM}Results:{RESET} {json_path}")
        print(f"  {DIM}Report: {RESET} {output_path}")
        
        # Update engagement if linked
        if args.engagement_id:
            eng = load_engagement(args.engagement_id)
            if eng:
                eng["modules_run"].append("darkweb")
                eng["scan_data"]["darkweb"] = check_result
                eng_path = DATA_DIR / "engagements.json"
                try:
                    with open(eng_path) as f:
                        all_eng = json.load(f)
                    for i, e in enumerate(all_eng):
                        if e["id"] == eng["id"]:
                            all_eng[i] = eng
                            break
                    with open(eng_path, "w") as f:
                        json.dump(all_eng, f, indent=2, default=str)
                except:
                    pass
        
    except ImportError:
        print(f"  {RED}✗{RESET} Install required packages:")
        print(f"    pip install requests dnspython")
    except Exception as e:
        print(f"  {RED}✗{RESET} Error: {str(e)}")


def cmd_help(args):
    print_banner()
    print(f"""
{BOLD}USAGE:{RESET}
    python main.py start <client_name> <target> [options]
    python main.py list
    python main.py run <engagement_id> [modules]
    python main.py report <engagement_id>

{BOLD}COMMANDS:{RESET}
{DIM}start{RESET}     Start a new audit engagement
{DIM}list{RESET}       List all engagements
{DIM}run{RESET}        Run scan modules on an engagement
{DIM}report{RESET}     Generate professional PDF report from scan data

{BOLD}EXAMPLES:{RESET}
  Start an engagement:
    {CYAN}python main.py start "Acme Corp" example.com --service smallbiz{RESET}

  Run all scan modules:
    {CYAN}python main.py run ENG-240101-ABC123 --modules all{RESET}

  Run specific modules:
    {CYAN}python main.py run ENG-240101-ABC123 --modules recon web{RESET}

  Generate PDF report:
    {CYAN}python main.py report ENG-240101-ABC123{RESET}

{BOLD}MODULES:{RESET}
{DIM}recon{RESET}    Port scan, web services, DNS enumeration, SSL check, subdomain discovery, version detection
{DIM}web{RESET}       Web vuln detection — headers, cookies, CORS, redirects, robots.txt, tech fingerprinting
{DIM}osint{RESET}      Domain public info, email footprint, WHOIS lookup, DNS, social media
{DIM}vuln{RESET}       Vulnerability detection across all services — CVE matching, version-specific vulns
{DIM}darkweb{RESET}  Check if emails, domains, or passwords appear in known data breaches (HIBP)
{DIM}all{RESET}        Run every module (recon + web + osint + vuln with CVE enrichment)

{BOLD}DARK WEB CHECK:{RESET}
  {CYAN}python main.py darkweb --email user@company.com{RESET}
  {CYAN}python main.py darkweb --domain company.com{RESET}
  {CYAN}python main.py darkweb ENG-XXX  (auto-extracts emails from OSINT data){RESET}

{BOLD}OPTIONS:{RESET}
  --service <type>     micro | smallbiz | pentest (default: micro)
  --devices <count>    Number of devices (default: 1)
  --addons <list>      Comma-separated: sqlmap,bruteforce,exploit

{BOLD}SERVICES:{RESET}
{DIM}micro{RESET}      Micro-business audit ($1,000, 1-5 devices)
{DIM}smallbiz{RESET}    Small business audit ($2,200, 5-15 devices)
{DIM}pentest{RESET}     Full penetration test (custom quote)
""")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        prog="trintech-audit",
        description="TrinTech Digital Defense — Full Network Audit Suite",
        add_help=True,
    )
    sub = parser.add_subparsers(dest="command")

    # start
    p_start = sub.add_parser("start", help="Start a new audit engagement")
    p_start.add_argument("client", help="Client name")
    p_start.add_argument("target", help="Target IP, hostname, or CIDR range")
    p_start.add_argument("--service", default="micro", choices=["micro", "smallbiz", "pentest"],
                         help="Service tier (default: micro)")
    p_start.add_argument("--devices", type=int, default=1, help="Number of devices")
    p_start.add_argument("--addons", default="", help="Comma-separated addons: sqlmap,bruteforce,exploit")
    p_start.set_defaults(func=cmd_start)

    # list
    p_list = sub.add_parser("list", help="List all engagements")
    p_list.set_defaults(func=cmd_list)

    # run
    p_run = sub.add_parser("run", help="Run scan modules on an engagement")
    p_run.add_argument("engagement_id", help="Engagement ID")
    p_run.add_argument("--modules", default="recon,web", help="Modules to run: recon,web,osint,vuln,all")
    p_run.set_defaults(func=cmd_run)

    # report
    p_report = sub.add_parser("report", help="Generate PDF report")
    p_report.add_argument("engagement_id", help="Engagement ID")
    p_report.set_defaults(func=cmd_report)

    # help
    p_help = sub.add_parser("help", help="Show this help")
    p_help.set_defaults(func=cmd_help)

    # darkweb
    p_dw = sub.add_parser("darkweb", help="Check if client data appears in known data breaches")
    p_dw.add_argument("engagement_id", nargs="?", help="Engagement ID (auto-extracts emails from OSINT)")
    p_dw.add_argument("--emails", default=None, help="Comma-separated emails to check")
    p_dw.add_argument("--email", default=None, help="Single email to check")
    p_dw.add_argument("--domain", default=None, help="Domain to check for breach involvement")
    p_dw.add_argument("--target", default=None, help="Target hostname/domain (alias for --domain)")
    p_dw.add_argument("--passwords", default=None, help="Comma-separated passwords to check (demo only)")
    p_dw.set_defaults(func=cmd_darkweb)

    # If no args, show help
    if len(sys.argv) < 2:
        cmd_help(None)
        return

    args = parser.parse_args()

    # If no command (just program name)
    if not args.command:
        cmd_help(None)
        return

    args.func(args)


if __name__ == "__main__":
    main()
