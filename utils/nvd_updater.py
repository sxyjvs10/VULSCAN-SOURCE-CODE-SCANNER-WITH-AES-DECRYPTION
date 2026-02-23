import requests
import time
from vdb import VulnerabilityDB

class NVDUpdater:
    def __init__(self, db_path="vuln_data.db"):
        self.db = VulnerabilityDB(db_path)
        # NVD API v2 (requires API key for better rate limits, using demo mode)
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def update(self, keyword="jquery", limit=20):
        """
        Fetches latest CVEs for a specific keyword/software.
        In a real scenario, this would iterate through common libraries.
        """
        print(f"[*] Updating vulnerability database for: {keyword}...")
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': limit
        }
        
        try:
            response = requests.get(self.base_url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                count = 0
                for item in vulnerabilities:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id')
                    descriptions = cve.get('descriptions', [])
                    desc = next((d['value'] for d in descriptions if d['lang'] == 'en'), "No description available.")
                    
                    # Get metrics (CVSS v3.1 preferred)
                    metrics = cve.get('metrics', {})
                    cvss_data = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    
                    # Get affected software/versions
                    software = keyword
                    version = "UNKNOWN"
                    
                    try:
                        configs = cve.get('configurations', [])
                        for config in configs:
                            for node in config.get('nodes', []):
                                for match in node.get('cpeMatch', []):
                                    if match.get('vulnerable'):
                                        criteria = match.get('criteria', '')
                                        # CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
                                        parts = criteria.split(':')
                                        if len(parts) > 4:
                                            product = parts[4].lower()
                                            # Strict check: product must match keyword
                                            if product != keyword.lower():
                                                continue

                                        if 'versionEndExcluding' in match:
                                            version = f"<{match['versionEndExcluding']}"
                                            break
                                        elif 'versionEndIncluding' in match:
                                            version = f"<={match['versionEndIncluding']}"
                                            break
                                if version != "UNKNOWN": break
                            if version != "UNKNOWN": break
                    except Exception:
                        pass
                    
                    if version == "UNKNOWN":
                        continue # Skip if no version constraint found or mismatched product
                    
                    pub_date = cve.get('published', '')

                    self.db.add_vulnerability(cve_id, software, version, severity, desc, pub_date)
                    count += 1
                
                self.db.set_last_update()
                print(f"[+] Successfully added/updated {count} vulnerabilities for {keyword}.")
            else:
                print(f"[-] NVD API error: {response.status_code}")
        except Exception as e:
            print(f"[-] Failed to update NVD database: {e}")

if __name__ == "__main__":
    updater = NVDUpdater()
    # Seed with some common web libraries
    for lib in ["jquery", "bootstrap", "angularjs", "react", "vue", "crypto-js"]:
        updater.update(lib, limit=10)
        time.sleep(2) # Respect NVD rate limits
