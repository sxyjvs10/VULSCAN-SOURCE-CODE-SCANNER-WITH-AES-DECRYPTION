import json
import datetime
import sys

# ANSI Color Codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GREY = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"

class Reporter:
    def __init__(self, findings, verbose=False):
        self.findings = findings
        self.verbose = verbose
        self.severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

    def _get_color(self, severity):
        if severity == 'CRITICAL': return RED + BOLD
        if severity == 'HIGH': return RED
        if severity == 'MEDIUM': return YELLOW
        if severity == 'LOW': return BLUE
        if severity == 'INFO': return GREEN
        return RESET

    def print_summary(self):
        # Sort findings by severity
        self.findings.sort(key=lambda x: self.severity_order.get(x.get('severity', 'INFO'), 5))

        print(f"\n{BOLD}{CYAN}╔{'═'*58}╗{RESET}")
        print(f"{BOLD}{CYAN}║{'SCAN SUMMARY':^58}║{RESET}")
        print(f"{BOLD}{CYAN}╠{'═'*58}╣{RESET}")
        print(f"║ {BOLD}{'SEVERITY':<12}{RESET} │ {BOLD}{'COUNT':<43}{RESET}║")
        print(f"{CYAN}╟{'─'*13}┼{'─'*44}╢{RESET}")
        
        # Count by severity
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            sev = f.get('severity', 'INFO')
            counts[sev] = counts.get(sev, 0) + 1
        
        total_count = 0
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = counts.get(sev, 0)
            total_count += count
            if count > 0:
                color = self._get_color(sev)
                print(f"║ {color}{sev:<12}{RESET} │ {count:<43}║")
        
        print(f"{CYAN}╠{'═'*58}╣{RESET}")
        print(f"║ {BOLD}{'TOTAL':<12}{RESET} │ {BOLD}{total_count:<43}{RESET}║")
        print(f"{CYAN}╚{'═'*58}╝{RESET}")
        
        if not self.findings:
            print(f"\n{GREEN}[+] No vulnerabilities found.{RESET}")
            return

        print(f"\n{BOLD}{UNDERLINE}DETAILED FINDINGS{RESET}")

        # Group by type for display
        grouped = {}
        for f in self.findings:
            t = f['type']
            if t not in grouped: grouped[t] = []
            grouped[t].append(f)
        
        # Sort grouped keys by severity of the first item
        sorted_types = sorted(grouped.keys(), key=lambda t: self.severity_order.get(grouped[t][0].get('severity', 'INFO'), 5))

        for t in sorted_types:
            items = grouped[t]
            first_item = items[0]
            sev = first_item.get('severity', 'INFO')
            color = self._get_color(sev)
            
            print(f"\n{color}[{sev}] {t}{RESET} {GREY}({len(items)} found){RESET}")
            print(f"{BOLD}Description:{RESET} {first_item.get('description', 'N/A')}")
            print(f"{BOLD}Remediation:{RESET} {first_item.get('remediation', 'N/A')}")
            
            # Decide on slice
            display_items = items if self.verbose else items[:3]
            
            for i, item in enumerate(display_items):
                source_tag = f"{MAGENTA}[DYNAMIC]{RESET} " if item.get('source') in ['DYNAMIC_PROBE', 'DYNAMIC', 'DYNAMIC_INTERCEPTION'] else ""
                
                print(f"  {CYAN}{i+1}.{RESET} {BOLD}URL:{RESET} {source_tag}{item.get('url', 'Unknown')}")
                
                line_num = item.get('line', 0)
                if line_num:
                    print(f"     {BOLD}Line:{RESET} {line_num}")
                
                match_val = item.get('match', 'N/A')
                # Truncate match if too long
                if len(str(match_val)) > 100:
                    match_val = str(match_val)[:97] + "..."
                print(f"     {BOLD}Match:{RESET} {RED}{match_val}{RESET}")
                
                if item.get('decoded_value'):
                    print(f"     {GREEN}{BOLD}Decoded:{RESET} {item['decoded_value']}")
                
                context = item.get('context', '')
                if context:
                    # Clean up newlines/tabs for display
                    context = context.replace('\n', ' ').replace('\r', '').strip()
                    if len(context) > 120:
                        context = context[:117] + "..."
                    print(f"     {BOLD}Context:{RESET} {GREY}{context}{RESET}")
            
            if not self.verbose and len(items) > 3:
                print(f"     {YELLOW}... and {len(items)-3} more instances (use -v to see all).{RESET}")

    def save(self, filepath):
        print(f"[*] Saving report to {filepath}...")
        
        if filepath.endswith('.html'):
            self.save_html(filepath)
        else:
            self.save_json(filepath)

    def save_json(self, filepath):
        report_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'details': self.findings
        }
        try:
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=4)
            print(f"[+] JSON Report saved successfully.")
        except Exception as e:
            print(f"[-] Failed to save JSON report: {e}")

    def save_html(self, filepath):
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>VULSCAN Scan Report</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
                h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                .summary-box { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
                table { border-collapse: collapse; width: 100%; margin-top: 10px; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #34495e; color: white; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                tr:hover { background-color: #f1f1f1; }
                
                .critical { color: #721c24; background-color: #f8d7da; font-weight: bold; }
                .high { color: #dc3545; font-weight: bold; }
                .medium { color: #ffc107; font-weight: bold; }
                .low { color: #17a2b8; font-weight: bold; }
                .info { color: #28a745; font-weight: bold; }
                
                .finding-block { background: white; padding: 15px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 15px; border-left: 5px solid #ccc; }
                .finding-block.critical { border-left-color: #dc3545; }
                .finding-block.high { border-left-color: #ff4444; }
                .finding-block.medium { border-left-color: #ffbb33; }
                .finding-block.low { border-left-color: #00C851; }
                
                pre { background-color: #2d2d2d; color: #f8f8f2; padding: 10px; border-radius: 3px; overflow-x: auto; font-family: 'Consolas', monospace; }
                code { background-color: #eee; padding: 2px 5px; border-radius: 3px; color: #d63384; }
            </style>
        </head>
        <body>
            <h1>VULSCAN Scan Report</h1>
            <div class="summary-box">
                <p><strong>Timestamp:</strong> {{TIMESTAMP}}</p>
                <p><strong>Total Findings:</strong> {{TOTAL}}</p>
                {{SUMMARY_TABLE}}
            </div>
            
            <h2>Detailed Findings</h2>
            {{FINDINGS_LIST}}
        </body>
        </html>
        """
        
        # Summary Table
        summary_rows = ""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            counts[f.get('severity', 'INFO')] += 1
            
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if counts[sev] > 0:
                summary_rows += f"<tr><td class='{{sev.lower()}}'>{{sev}}</td><td>{{counts[sev]}}</td></tr>"
        
        summary_table = f"<table><tr><th>Severity</th><th>Count</th></tr>{{summary_rows}}</table>"

        # Findings List
        findings_html = ""
        for f in self.findings:
            sev = f.get('severity', 'INFO')
            sev_class = sev.lower()
            
            findings_html += f'<div class="finding-block {sev_class}">\n'
            findings_html += f'<h3><span class="{sev_class}">[{sev}]</span> {f["type"]}</h3>\n'
            findings_html += f'<p><strong>URL:</strong> <a href="{f["url"]}">{f["url"]}</a></p>\n'
            findings_html += f'<p><strong>Description:</strong> {f.get("description","")}</p>\n'
            findings_html += f'<p><strong>Remediation:</strong> {f.get("remediation","")}</p>\n'
            findings_html += f'<p><strong>Match:</strong> <code>{f.get("match","")}</code></p>\n'
            if f.get("decoded_value"):
                findings_html += f'<p><strong>Decoded:</strong> {f["decoded_value"]}</p>\n'
            findings_html += f'<pre>{f.get("context","")}</pre>\n'
            findings_html += '</div>\n'
        
        html = html_template.replace("{{TIMESTAMP}}", datetime.datetime.now().isoformat())
        html = html.replace("{{TOTAL}}", str(len(self.findings)))
        html = html.replace("{{SUMMARY_TABLE}}", summary_table)
        html = html.replace("{{FINDINGS_LIST}}", findings_html)
        
        try:
            with open(filepath, 'w') as f:
                f.write(html)
            print(f"[+] HTML Report saved successfully.")
        except Exception as e:
            print(f"[-] Failed to save HTML report: {e}")