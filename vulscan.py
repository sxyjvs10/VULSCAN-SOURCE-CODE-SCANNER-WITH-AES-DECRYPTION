#!/usr/bin/env python3
import argparse
import sys
import os
import hashlib
import time

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent directory to path to allow importing modules from root
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.behavior import SessionManager
from core.mapper import Crawler
from core.engine import Analyzer
from core.report import Reporter
from utils.login_manager import LoginManager
from core.vdb import VulnerabilityDB
from utils.nvd_updater import NVDUpdater
from core.dorker import GoogleDorker
from core.discovery import PathEnumerator

def main():
    parser = argparse.ArgumentParser(description="VULSCAN - Advanced Web Application Source Code Scanner (Client-Side)")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com/dashboard)")
    parser.add_argument("-c", "--cookies", help="Session Cookies (e.g., 'sessionid=xyz; auth=abc')")
    parser.add_argument("-H", "--headers", action="append", help="Custom Headers (e.g., 'Authorization: Bearer token')")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Crawling Depth (default: 3)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", help="Output file (JSON/HTML)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL Verification")
    parser.add_argument("-b", "--browser", action="store_true", help="Use Headless Browser (Selenium) for crawling")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output for all findings")
    parser.add_argument("--save-content", action="store_true", help="Save all crawled content to local files")
    parser.add_argument("--min-severity", choices=['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW', help="Minimum severity to report (default: LOW)")
    parser.add_argument("--update-db", action="store_true", help="Update the local vulnerability database from NVD")
    
    # Auto-Login Arguments
    parser.add_argument("--login-url", help="Login Page URL for Auto-Login")
    parser.add_argument("--username", help="Username for Auto-Login")
    parser.add_argument("--password", help="Password for Auto-Login")
    
    # New Strategies
    parser.add_argument("--live-exploit", action="store_true", help="Inject AES Interceptor and monitor for keys (Requires -b)")
    parser.add_argument("--scan-all", action="store_true", help="Run ALL strategies (Static, Dynamic) to find keys.")
    
    # Discovery Features
    parser.add_argument("--dorks", action="store_true", help="Generate and display Google Dorks for the target domain")
    parser.add_argument("--hidden-scan", action="store_true", help="Perform a directory brute-force scan to find hidden files/folders")
    parser.add_argument("--wordlist", help="Custom wordlist file for --hidden-scan (optional)")

    args = parser.parse_args()

    # Initialize DB & Cookies (Used by both normal and scan-all modes)
    print("[*] Initializing VULSCAN...")
    vuln_db = VulnerabilityDB()
    final_cookies = args.cookies

    # --- Discovery & Reconnaissance Features ---
    if args.dorks:
        try:
            from urllib.parse import urlparse
            domain = urlparse(args.url).netloc
            dorker = GoogleDorker(domain)
            dorker.print_dorks()
            print("-" * 60)
        except Exception as e:
            print(f"[-] Google Dork generation failed: {e}")

    if args.hidden_scan:
        print("[*] Starting Hidden Directory Scan...")
        # Load wordlist if provided
        wordlist = None
        if args.wordlist:
            try:
                with open(args.wordlist, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[-] Failed to load wordlist: {e}")
                sys.exit(1)
        
        enumerator = PathEnumerator(args.url, wordlist=wordlist, threads=args.threads)
        found_paths = enumerator.start()
        print(f"[+] Hidden Scan Complete. Found {len(found_paths)} paths.")
        for p in found_paths:
             print(f"    - {p['url']} (Status: {p['status']}, Size: {p['size']})")
        print("-" * 60)
    # -------------------------------------------

    # Helper to get payload path
    payload_path = os.path.join(os.path.dirname(__file__), "payloads", "aes_live.js")

    # Handle Scan All Mode
    if args.scan_all:
        print("[*] STARTING COMPREHENSIVE SCAN (ALL STRATEGIES)...")
        print("="*60)
        
        findings_summary = {
            "static": 0,
            "dynamic": 0,
            "keys_found": []
        }

        # 0. Discovery & Reconnaissance (New)
        print("\n[PHASE 0] Discovery & Reconnaissance...")
        try:
            from urllib.parse import urlparse
            domain = urlparse(args.url).netloc
            dorker = GoogleDorker(domain)
            dorker.print_dorks()
        except Exception as e:
            print(f"[-] Dork generation failed: {e}")

        print("\n[*] Starting Hidden Directory Scan (Default Wordlist)...")
        try:
            enumerator = PathEnumerator(args.url, threads=args.threads)
            found_paths = enumerator.start()
            print(f"[+] Hidden Scan Complete. Found {len(found_paths)} paths.")
            # We don't print all 100+ paths here to avoid cluttering the summary view, 
            # but we could save them or print a sample.
            for p in found_paths[:5]:
                 print(f"    - {p['url']} (Status: {p['status']}, Size: {p['size']})")
            if len(found_paths) > 5:
                print(f"    ... and {len(found_paths)-5} more.")
        except Exception as e:
            print(f"[-] Hidden scan failed: {e}")

        # 1. Static Scan
        print("\n[PHASE 1] Static Analysis (Crawling & Source Code Scan)...")
        # Ensure browser is off for pure static crawl unless requested, but let's default to fast crawl
        session_manager_static = SessionManager(cookies=final_cookies, headers=args.headers, ssl_verify=not args.insecure, use_browser=False)
        try:
            crawler = Crawler(session_manager_static, args.url, depth=args.depth, max_workers=args.threads)
            crawled_pages, network_urls = crawler.start()
            
            analyzer = Analyzer(vuln_db=vuln_db)
            static_findings = analyzer.scan(crawled_pages, network_urls)
            findings_summary["static"] = len(static_findings)
            for f in static_findings:
                if f['severity'] in ['CRITICAL', 'HIGH']:
                    # Use decoded value if available (for decrypted secrets), otherwise use the match
                    if f.get('decoded_value'):
                        val = f.get('decoded_value')
                    else:
                        val = f.get('match')
                        
                    # Clean up context for display if needed
                    if "SUSPICIOUS_FUNC_ARG_KEY" in f['type']:
                         # Extract just the key string if possible
                         import re
                         m = re.search(r'["\']([a-zA-Z0-9]{16,32})["\']', val)
                         if m: val = m.group(1)
                    
                    findings_summary["keys_found"].append(f"[Static] {f['type']}: {val}")
        except Exception as e:
            print(f"[-] Static Scan Failed: {e}")

        # 2. Dynamic Scan
        print("\n[PHASE 2] Dynamic Analysis (Browser Interception)...")
        session_manager_dynamic = SessionManager(
            cookies=final_cookies, 
            headers=args.headers, 
            ssl_verify=not args.insecure, 
            use_browser=True, 
            live_exploit_script=payload_path
        )
        try:
            # Just visit the main URL and wait for interception
            print(f"[*] Visiting {args.url} with AES Interceptor (Waiting 15s)...")
            session_manager_dynamic.get(args.url)
            
            # Force load unlinked JS assets into the current page context
            unlinked_js = [u for u in crawled_pages.keys() if u.endswith('.js') and u != args.url]
            if unlinked_js:
                print(f"[*] Sideloading {len(unlinked_js)} unlinked scripts into browser context...")
                for js_url in unlinked_js:
                    session_manager_dynamic.driver.execute_script(f"""
                        var s = document.createElement('script');
                        s.src = '{js_url}';
                        document.head.appendChild(s);
                    """)

            # Give it time to run scripts
            time.sleep(15) 
            # Force read one last time just in case
            session_manager_dynamic.read_console_logs()
            
            logs = session_manager_dynamic.captured_logs
            findings_summary["dynamic"] = len(logs)
            for log in logs:
                if any(indicator in log for indicator in ["KEY", "FOUND GLOBAL", "🔓", "🔥", "Auto-Decrypted"]):
                    findings_summary["keys_found"].append(f"[Dynamic] {log}")
        except Exception as e:
            print(f"[-] Dynamic Scan Failed: {e}")
        finally:
            session_manager_dynamic.close()

        # Final Report
        print("\n" + "="*60)
        print("COMPREHENSIVE SCAN COMPLETE")
        print(f"Static Findings: {findings_summary['static']}")
        print(f"Dynamic Interceptions: {findings_summary['dynamic']}")
        
        if findings_summary["keys_found"]:
            print("\n[+] CONFIRMED KEYS/SECRETS FOUND:")
            for k in findings_summary["keys_found"]:
                print(f"  -> {k}")
        else:
            print("\n[-] No obvious keys found across all strategies.")

        # Save Report if requested
        if args.output:
            all_findings = []
            # Add static findings
            if 'static_findings' in locals():
                all_findings.extend(static_findings)
            
            # Convert dynamic logs to findings objects
            for log in logs:
                all_findings.append({
                    'url': args.url,
                    'type': 'DYNAMIC_INTERCEPTION',
                    'severity': 'HIGH' if any(x in log for x in ["KEY", "IV", "Decrypted"]) else 'INFO',
                    'description': 'Dynamic interception of cryptographic operation or secret.',
                    'remediation': 'Review the intercepted data context.',
                    'match': log[:100] + "...",
                    'context': log,
                    'line': 0,
                    'source': 'DYNAMIC'
                })
            
            # Add pattern findings if any (simulated)
            for k in findings_summary["keys_found"]:
                if "[Pattern]" in k:
                     all_findings.append({
                        'url': args.url,
                        'type': 'PATTERN_MATCH',
                        'severity': 'CRITICAL',
                        'description': 'Specific obfuscation pattern matched and deobfuscated.',
                        'remediation': 'Revoke the key.',
                        'match': k,
                        'context': k,
                        'line': 0,
                        'source': 'PATTERN'
                    })

            print(f"[*] Saving comprehensive report to {args.output}...")
            reporter = Reporter(all_findings, verbose=args.verbose)
            reporter.save(args.output)
        
        sys.exit(0)

    if args.live_exploit:
        args.browser = True # Force browser mode
        print("[*] Live Exploit Mode Enabled: Injecting AES Interceptor...")

    if args.browser and args.threads > 1:
        print("[!] Warning: Using multiple threads with a single browser instance operates serially. For best browser performance, use -t 1.")

    # Handle DB Update
    if args.update_db:
        print("[*] Updating Vulnerability Database...")
        updater = NVDUpdater()
        for lib in ["jquery", "bootstrap", "angularjs", "react", "vue", "crypto-js", "lodash", "moment"]:
            updater.update(lib, limit=15)
        print("[+] Vulnerability Database update complete.")
        if not args.url: sys.exit(0)

    # 0. Auto-Login (if requested)
    if args.login_url and args.username and args.password:
        login_manager = LoginManager(args.login_url, args.username, args.password)
        cookies_dict = login_manager.login()
        if cookies_dict:
            cookie_str = login_manager.get_cookie_string()
            print(f"[+] Auto-Login Cookie: {cookie_str}")
            if final_cookies:
                final_cookies += f"; {cookie_str}"
            else:
                final_cookies = cookie_str
        else:
            print("[-] Auto-Login failed to retrieve cookies.")

    # 1. Setup Session
    live_script = payload_path if args.live_exploit else None
    session_manager = SessionManager(
        cookies=final_cookies, 
        headers=args.headers, 
        ssl_verify=not args.insecure, 
        use_browser=args.browser,
        live_exploit_script=live_script
    )
    if not session_manager.verify_connection(args.url):
        print("[-] Connection failed or login invalid. Check URL/Cookies.")
        if args.browser:
            session_manager.close()
        sys.exit(1)

    try:
        # 2. Crawl (Map)
        print(f"[*] Starting authenticated crawl on {args.url} (Depth: {args.depth}, Threads: {args.threads})...")
        crawler = Crawler(session_manager, args.url, depth=args.depth, max_workers=args.threads)
        crawled_pages, network_urls = crawler.start()
        print(f"[+] Found {len(crawled_pages)} unique pages/assets.")
        if network_urls:
            print(f"[+] Identified {len(network_urls)} unique assets via Network Logs.")

        if args.save_content:
            os.makedirs("crawled_data", exist_ok=True)
            for url, content in crawled_pages.items():
                if len(url) > 100 or url.startswith("data:"):
                    filename = hashlib.md5(url.encode()).hexdigest() + ".content"
                else:
                    filename = url.replace("https://", "").replace("http://", "").replace("/", "_").replace("?", "_").replace("=", "_").replace(":", "_")
                
                try:
                    with open(os.path.join("crawled_data", filename), "w") as f:
                        f.write(content)
                except Exception as e:
                    print(f"[!] Warning: Could not save content for {url[:50]}... Error: {e}")
            print(f"[+] Saved content for {len(crawled_pages)} pages to 'crawled_data/'")

        

        # 3. Analyze (Engine)
        print("[*] Analyzing source code for vulnerabilities...")
        analyzer = Analyzer(vuln_db=vuln_db)
        findings = analyzer.scan(crawled_pages, network_urls)
        
        # Filter Findings
        severity_map = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'UNKNOWN': 0}
        min_score = severity_map.get(args.min_severity, 0)
        
        filtered_findings = [
            f for f in findings 
            if severity_map.get(f.get('severity', 'INFO'), 0) >= min_score
        ]
        
        if len(findings) > len(filtered_findings):
            print(f"[*] Filtered out {len(findings) - len(filtered_findings)} findings below {args.min_severity} severity.")

        # 4. Report
        print("[*] Generating report...")
        reporter = Reporter(filtered_findings, verbose=args.verbose)
        reporter.print_summary()
        if args.output:
            reporter.save(args.output)
    finally:
        if args.browser:
            session_manager.close()

if __name__ == "__main__":
    main()
