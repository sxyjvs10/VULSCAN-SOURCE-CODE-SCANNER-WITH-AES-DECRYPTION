import json
import datetime

# ANSI Color Codes
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
GREEN = "\033[92m"
RESET = "\033[0m"
BOLD = "\033[1m"

class Reporter:
    def __init__(self, findings, verbose=False):
        self.findings = findings
        self.verbose = verbose
        self.severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

    def print_summary(self):
        # Sort findings by severity
        self.findings.sort(key=lambda x: self.severity_order.get(x.get('severity', 'INFO'), 5))

        print(f"\n{BOLD}### Scan Summary{RESET}")
        print(f"| {'Severity':<12} | {'Count':<8} |")
        print(f"| {'-'*12} | {'-'*8} |")
        
        # Count by severity
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            sev = f.get('severity', 'INFO')
            counts[sev] = counts.get(sev, 0) + 1
        
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if counts[sev] > 0:
                color = self._get_color(sev)
                print(f"| {color}{sev:<12}{RESET} | {counts[sev]:<8} |")
        
        print(f"| {BOLD}{'Total':<12}{RESET} | {BOLD}{len(self.findings):<8}{RESET} |")
        
        print(f"\n{BOLD}### Detailed Findings{RESET}")

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
            
            print(f"\n{color}[{sev}] {t} ({len(items)} found){RESET}")
            print(f"{BOLD}Description:{RESET} {first_item.get('description', 'N/A')}")
            print(f"{BOLD}Remediation:{RESET} {first_item.get('remediation', 'N/A')}")
            
            # Decide on slice
            display_items = items if self.verbose else items[:3]
            
            for i, item in enumerate(display_items):
                source_tag = f"{RED}[NETWORK]{RESET} " if item.get('source') == 'NETWORK' else ""
                print(f"  {i+1}. URL: {source_tag}{item['url']}")
                print(f"     Line: {item['line']}")
                print(f"     Match: {item['match']}")
                if item.get('decoded_value'):
                    print(f"     {GREEN}{BOLD}Decoded: {item['decoded_value']}{RESET}")
                print(f"     Context: {BLUE}...{item['context']}...{RESET}")
            
            if not self.verbose and len(items) > 3:
                print(f"     {YELLOW}... and {len(items)-3} more (use -v to see all).{RESET}")

    def _get_color(self, severity):
        if severity == 'CRITICAL': return RED + BOLD
        if severity == 'HIGH': return RED
        if severity == 'MEDIUM': return YELLOW
        if severity == 'LOW': return BLUE
        if severity == 'INFO': return GREEN
        return RESET

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
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f4f4; }
                h1 { color: #333; }
                table { border-collapse: collapse; width: 100%; box-shadow: 0 0 20px rgba(0,0,0,0.1); background-color: white; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #007bff; color: white; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                tr:hover { background-color: #f1f1f1; }
                .critical { color: #721c24; background-color: #f8d7da; font-weight: bold; }
                .high { color: #dc3545; font-weight: bold; }
                .medium { color: #ffc107; font-weight: bold; }
                .low { color: #17a2b8; font-weight: bold; }
                .info { color: #28a745; font-weight: bold; }
                pre { background-color: #eee; padding: 5px; border-radius: 3px; overflow-x: auto; }
            </style>
        </head>
        <body>
            <h1>VULSCAN Scan Report</h1>
            <p><strong>Timestamp:</strong> {{TIMESTAMP}}</p>
            <p><strong>Total Findings:</strong> {{TOTAL}}</p>
            
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>URL</th>
                    <th>Line</th>
                    <th>Match</th>
                    <th>Context</th>
                </tr>
                {{ROWS}}
            </table>
        </body>
        </html>
        """
        
        rows = ""
        # Ensure sorted before generating HTML
        self.findings.sort(key=lambda x: self.severity_order.get(x.get('severity', 'INFO'), 5))
        
        for f in self.findings:
            sev = f.get('severity', 'INFO')
            sev_class = sev.lower()
            rows += f"<tr><td class='{sev_class}'>{sev}</td><td>{f['type']}</td><td>{f.get('description','')}</td><td>{f['url']}</td><td>{f['line']}</td><td><code>{f['match']}</code></td><td><pre>{f['context']}</pre></td></tr>"
        
        html = html_template.replace("{{TIMESTAMP}}", datetime.datetime.now().isoformat())
        html = html.replace("{{TOTAL}}", str(len(self.findings)))
        html = html.replace("{{ROWS}}", rows)
        
        try:
            with open(filepath, 'w') as f:
                f.write(html)
            print(f"[+] HTML Report saved successfully.")
        except Exception as e:
            print(f"[-] Failed to save HTML report: {e}")

