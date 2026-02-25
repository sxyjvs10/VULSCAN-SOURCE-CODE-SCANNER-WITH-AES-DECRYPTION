import requests
import threading
from urllib.parse import urljoin
import sys

# Common paths to check (Expanded list based on recon research and bug bounty trends)
DEFAULT_WORDLIST = [
    # --- Version Control ---
    ".git/HEAD", ".git/config", ".git/index", ".gitignore", 
    ".svn/entries", ".ds_store", ".hg/hgrc",

    # --- Configuration & Secrets ---
    ".env", ".env.example", ".env.prod", ".env.local", ".env.backup",
    "config.json", "config.js", "config.php", "config.yml", "config.yaml",
    "web.config", "php.ini", ".htaccess", "nginx.conf", "httpd.conf",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "sftp-config.json", ".npmrc", ".dockercfg", "docker-compose.yml", "Dockerfile",
    "composer.json", "composer.lock", "package.json", "package-lock.json",
    "secrets.yml", "secrets.json", "appsettings.json", "appsettings.Development.json",
    "database.yml", "settings.py", "local_settings.py",

    # --- SSH & Shell History ---
    ".ssh/id_rsa", ".ssh/id_rsa.pub", ".ssh/known_hosts", ".ssh/authorized_keys",
    "id_rsa", "id_rsa.pub", "key.pem", "private.key",
    ".bash_history", ".zsh_history", ".mysql_history", ".history",

    # --- Backups & Dumps ---
    "backup", "backup.zip", "backup.tar", "backup.tar.gz", "backup.sql",
    "site.zip", "site.tar.gz", "www.zip", "www.tar.gz",
    "dump.sql", "db.sql", "database.sql", "users.sql", "data.sql",
    "logs.tar.gz", "log.tar.gz",

    # --- Logs & Status ---
    "error.log", "access.log", "debug.log", "application.log", "server.log",
    "php_errors.log", "storage/logs/laravel.log",
    "server-status", "nginx_status", "tomcat/manager/html",

    # --- Admin & Panels ---
    "admin", "administrator", "dashboard", "cpanel", "phpmyadmin", "wp-admin",
    "admin.php", "admin/login.php", "panel", "control", "manage",

    # --- API & Dev ---
    "api", "v1", "v2", "graphql", "swagger.json", "swagger-ui.html", "api-docs",
    "actuator/health", "actuator/env", "actuator/metrics", "health", "metrics", "info",
    "debug", "test.php", "phpinfo.php", "info.php", "temp", "tmp",
    
    # --- Cloud & Metadata (If relevant context) ---
    "aws/credentials", ".aws/credentials", "adc.json", "gcp-creds.json",

    # --- Common Login/Register ---
    "login", "register", "signin", "signup", "auth",

    # --- Standards ---
    "robots.txt", "sitemap.xml", ".well-known/security.txt", "humans.txt"
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
            
            # Interesting status codes
            if status in [200, 301, 302, 401, 403, 500]:
                size = len(resp.content)
                # Filter out standard 404s that might return 200 (soft 404 detection would be better but simple for now)
                
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
        
        from concurrent.futures import ThreadPoolExecutor
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self._check_path, expanded_list)
        
        return self.found_paths