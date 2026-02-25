import requests
import threading
from urllib.parse import urljoin
import sys

# Common paths to check (Small list for default scan)
DEFAULT_WORDLIST = [
    ".git/HEAD", ".git/config", ".env", ".htaccess", "backup", "bak", "admin", "administrator",
    "dashboard", "api", "config", "debug", "login", "register", "wp-admin", "wp-config.php",
    "phpinfo.php", "test.php", "temp", "tmp", "db.sql", "database.sql", "users.sql",
    "secrets.yml", "appsettings.json", "web.config", "server-status", "health", "metrics",
    "v1", "v2", "graphql", "swagger.json", "swagger-ui.html", "actuator/health"
]

class PathEnumerator:
    def __init__(self, target_url, wordlist=None, threads=10, timeout=5, extensions=None):
        self.target_url = target_url.rstrip('/') + '/'
        self.wordlist = wordlist if wordlist else DEFAULT_WORDLIST
        self.threads = threads
        self.timeout = timeout
        self.extensions = extensions if extensions else []
        self.found_paths = []
        self.lock = threading.Lock()
    
    def _check_path(self, path):
        url = urljoin(self.target_url, path)
        try:
            resp = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
            status = resp.status_code
            
            if status in [200, 301, 302, 401, 403]:
                size = len(resp.content)
                with self.lock:
                    print(f"[{status}] {url} (Size: {size})")
                    self.found_paths.append({
                        'url': url,
                        'status': status,
                        'size': size
                    })
        except requests.exceptions.RequestException:
            pass

    def start(self):
        print(f"[*] Starting directory brute-force on {self.target_url}...")
        print(f"[*] Wordlist size: {len(self.wordlist)}")
        
        # Expand with extensions if provided
        expanded_list = []
        for path in self.wordlist:
            expanded_list.append(path)
            for ext in self.extensions:
                expanded_list.append(f"{path}.{ext}")
        
        # Simple threading implementation
        # For a full implementation, consider ThreadPoolExecutor
        from concurrent.futures import ThreadPoolExecutor
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self._check_path, expanded_list)
        
        return self.found_paths
