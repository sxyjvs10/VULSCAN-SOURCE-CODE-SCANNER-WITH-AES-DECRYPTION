import re

class ComponentChecker:
    """
    Identifies third-party libraries and their versions from source code.
    """
    def __init__(self, vuln_db):
        self.db = vuln_db
        # Regex patterns to detect library and version from comments or code
        self.lib_patterns = [
            (r'jQuery\s+v?(\d+\.\d+\.\d+)', 'jquery'),
            (r'Bootstrap\s+v?(\d+\.\d+\.\d+)', 'bootstrap'),
            (r'AngularJS\s+v?(\d+\.\d+\.\d+)', 'angularjs'),
            (r'Vue\.js\s+v?(\d+\.\d+\.\d+)', 'vue'),
            (r'React\s+v?(\d+\.\d+\.\d+)', 'react'),
            (r'CryptoJS\s+v?(\d+\.\d+\.\d+)', 'crypto-js'),
            (r'Moment\.js\s+v?(\d+\.\d+\.\d+)', 'moment'),
            (r'Lodash\s+v?(\d+\.\d+\.\d+)', 'lodash')
        ]

    def check(self, url, content):
        findings = []
        for pattern, name in self.lib_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1)
                # print(f"[+] Detected {name} version {version} in {url}")
                
                # Check DB for vulnerabilities
                vulns = self.db.get_vulnerabilities(name, version)
                for v in vulns:
                    finding = {
                        'url': url,
                        'type': 'KNOWN_VULNERABILITY',
                        'severity': v['severity'],
                        'description': f"Known vulnerability in {name} {version}: {v['cve_id']}",
                        'remediation': f"Update {name} to a secure version. Details: {v['description'][:100]}...",
                        'match': f"{name} {version}",
                        'context': v['cve_id'],
                        'line': 1 # Generic line for the file
                    }
                    findings.append(finding)
        return findings
