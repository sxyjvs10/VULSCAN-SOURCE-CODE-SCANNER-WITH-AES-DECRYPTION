import hashlib
from bs4 import BeautifulSoup
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
import threading
import re
import xml.etree.ElementTree as ET

class Crawler:
    def __init__(self, session_manager, base_url, depth=2, max_workers=5):
        self.session_manager = session_manager
        self.base_url = base_url
        self.depth = depth
        self.max_workers = max_workers
        self.visited = set()
        self.lock = threading.Lock()
        self.extracted_content = {}  # {url: content}
        self.network_urls = set()    # Track URLs from network logs
        self.discovered_links = set() # To avoid re-queueing same discovery
        self.content_hashes = set()  # To avoid redundant analysis of identical content

    def start(self):
        # Auto-discovery
        self._discover_sitemap_robots()
        
        # Standard Crawl
        results = self._crawl_loop()
        
        # Heuristic Asset Fuzzing (Check for unlinked but common files)
        self.fuzz_assets()
        
        return results

    def fuzz_assets(self):
        COMMON_ASSETS = [
            "js/aes.js", "js/main.js", "js/app.js", "js/login.js", "js/crypto.js", 
            "js/utils.js", "js/common.js", "js/config.js", "js/script.js",
            "scripts/main.js", "scripts/common.js", "scripts/login.js", "scripts/app.js",
            "assets/js/main.js", "assets/js/app.js",
            "main.js", "common.js", "config.js", "app.js", "login.js"
        ]
        
        print(f"[*] Fuzzing for {len(COMMON_ASSETS)} common unlinked assets...")
        
        # Use a thread pool for faster fuzzing
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for asset_path in COMMON_ASSETS:
                full_url = urllib.parse.urljoin(self.base_url, asset_path)
                if full_url not in self.extracted_content:
                    futures[executor.submit(self.session_manager.get, full_url)] = full_url

            for future in as_completed(futures):
                url = futures[future]
                try:
                    resp = future.result()
                    if resp and resp.status_code == 200:
                        # Double check content type to ensure it's not a custom 404 page
                        ctype = resp.headers.get('Content-Type', '').lower()
                        if 'html' not in ctype: # Skip if it looks like a generic error page
                            print(f"[+] Discovered unlinked asset: {url}")
                            with self.lock:
                                self.extracted_content[url] = resp.text
                except Exception:
                    pass

    def _discover_sitemap_robots(self):
        print(f"[*] Attempting to auto-discover paths from robots.txt and sitemap.xml...")
        
        # 1. robots.txt
        robots_url = urllib.parse.urljoin(self.base_url, "/robots.txt")
        try:
            resp = self.session_manager.get(robots_url)
            if resp and resp.status_code == 200:
                print(f"[+] Found robots.txt")
                # Parse simple robots.txt
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            full_url = urllib.parse.urljoin(self.base_url, path)
                            if self.is_internal(full_url):
                                self.discovered_links.add(full_url)
        except Exception:
            pass

        # 2. sitemap.xml
        sitemap_url = urllib.parse.urljoin(self.base_url, "/sitemap.xml")
        try:
            resp = self.session_manager.get(sitemap_url)
            if resp and resp.status_code == 200:
                print(f"[+] Found sitemap.xml")
                # Simple XML parse
                try:
                    root = ET.fromstring(resp.text)
                    # Namespace might exist, ignore it for simple tag search or use simple iteration
                    for elem in root.iter():
                        if elem.tag.endswith('loc') and elem.text:
                            url = elem.text.strip()
                            if self.is_internal(url):
                                self.discovered_links.add(url)
                except ET.ParseError:
                    pass
        except Exception:
            pass
        
        if self.discovered_links:
            print(f"[+] discovered {len(self.discovered_links)} extra paths from robots/sitemap.")

    def _crawl_loop(self):
        with self.lock:
            self.visited.add(self.base_url)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # {future: url}
            futures = {executor.submit(self.process_url, self.base_url, 0): self.base_url}
            
            # Initial discovered links
            for link in self.discovered_links:
                if link not in self.visited:
                    self.visited.add(link)
                    futures[executor.submit(self.process_url, link, 1)] = link

            # Loop until all tasks are done
            while futures:
                done, _ = wait(futures, return_when=FIRST_COMPLETED)
                
                for future in done:
                    url = futures.pop(future)
                    try:
                        new_links = future.result()
                        if new_links:
                            for link, depth in new_links:
                                with self.lock:
                                    if link not in self.visited:
                                        self.visited.add(link)
                                        futures[executor.submit(self.process_url, link, depth)] = link
                    except Exception as e:
                        print(f"[-] Error processing {url}: {e}")
        
        return self.extracted_content, self.network_urls

    def process_url(self, url, current_depth):
        # 1. Skip non-analyzable binary/media assets early
        SKIP_EXT = ('.jpg', '.jpeg', '.png', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.zip', '.gz', '.tar', '.iso')
        if any(url.lower().endswith(ext) for ext in SKIP_EXT):
            return []

        print(f"[*] [Session Active] Crawling: {url} (Depth: {current_depth})")
        
        try:
            response = self.session_manager.get(url)
            if response and response.status_code == 200:
                # 2. Content Deduplication
                # Avoid re-scanning identical content served under different URLs
                text_content = response.text
                content_hash = hashlib.md5(text_content.encode('utf-8', errors='ignore')).hexdigest()
                
                with self.lock:
                    if content_hash in self.content_hashes:
                        return [] # Duplicate content
                    self.content_hashes.add(content_hash)

                # Check for login redirect (session invalidation)
                if "login" in response.url and "login" not in url:
                    print(f"[!] Warning: Possible session logout detected at {url}")

                ctype = response.headers.get('Content-Type', '').lower()
                
                # Store content if text-based
                if any(x in ctype for x in ['text', 'javascript', 'json', 'xml', 'markdown', 'md']):
                    with self.lock:
                        self.extracted_content[url] = response.text
                
                # Capture Network Logs (if browser is active)
                if self.session_manager.use_browser:
                    bg_logs = self.session_manager.get_network_logs()
                    if bg_logs:
                        print(f"[+] Captured {len(bg_logs)} background network responses from {url}")
                        for bg_url in bg_logs.keys():
                            print(f"  -> [BG] {bg_url}")
                        with self.lock:
                            for bg_url, bg_content in bg_logs.items():
                                self.extracted_content[bg_url] = bg_content
                                self.network_urls.add(bg_url)

                # Extract links if HTML and within depth
                new_links = []
                if 'text/html' in ctype and current_depth < self.depth:
                    new_links = self.extract_links(response.text, url, current_depth + 1)
                
                return new_links
            else:
                status = response.status_code if response else 'None'
                print(f"[-] Failed: {url} (Status: {status})")
                return []

        except Exception as e:
            print(f"[-] Exception crawling {url}: {e}")
            return []

    def extract_links(self, html_content, current_url, next_depth):
        links = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Standard <a> tags
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = urllib.parse.urljoin(current_url, href)
                if self.is_internal(full_url):
                    links.append((full_url, next_depth))
            
            # Form actions
            for form in soup.find_all('form', action=True):
                action = form['action']
                full_url = urllib.parse.urljoin(current_url, action)
                if self.is_internal(full_url):
                    links.append((full_url, next_depth))

            # Iframe srcs
            for iframe in soup.find_all('iframe', src=True):
                src = iframe['src']
                full_url = urllib.parse.urljoin(current_url, src)
                if self.is_internal(full_url):
                    links.append((full_url, next_depth))

            # Link hrefs (CSS, etc.)
            for link in soup.find_all('link', href=True):
                href = link['href']
                full_url = urllib.parse.urljoin(current_url, href)
                if self.is_internal(full_url):
                    links.append((full_url, next_depth))

            # AngularJS ng-href
            for a in soup.find_all(attrs={"ng-href": True}):
                href = a['ng-href']
                full_url = urllib.parse.urljoin(current_url, href)
                if self.is_internal(full_url):
                    links.append((full_url, next_depth))

            # <script> src
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_url = urllib.parse.urljoin(current_url, src)
                if self.is_internal(full_url):
                    links.append((full_url, next_depth))
            
            # Regex for internal paths in JS or HTML
            # Look for strings like "/FixedAssetMacom/..."
            path_pattern = r'["\'](/FixedAssetMacom/[\w/._?=-]+)["\']'
            matches = re.findall(path_pattern, html_content)
            for path in matches:
                full_url = urllib.parse.urljoin(current_url, path)
                if self.is_internal(full_url):
                    links.append((full_url, next_depth))
            
            # Simple JS window.location redirection
            js_loc_pattern = r'window\.location\.href\s*=\s*["\'](.*?)["\']'
            matches = re.findall(js_loc_pattern, html_content)
            for path in matches:
                full_url = urllib.parse.urljoin(current_url, path)
                if self.is_internal(full_url):
                    links.append((full_url, next_depth))
                    
        except Exception as e:
            print(f"[!] Error parsing content: {e}")
        
        return links


    def is_internal(self, url):
        base_netloc = urllib.parse.urlparse(self.base_url).netloc
        url_netloc = urllib.parse.urlparse(url).netloc
        return base_netloc == url_netloc

