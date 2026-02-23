import requests
import re
import urllib.parse
import time
import json
import threading
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService

class SessionManager:
    def __init__(self, cookies=None, headers=None, ssl_verify=True, use_browser=False, live_exploit_script=None):
        self.session = requests.Session()
        self.ssl_verify = ssl_verify
        self.use_browser = use_browser
        self.live_exploit_script = live_exploit_script
        self.driver = None
        self.driver_lock = threading.Lock()
        self.captured_logs = []  # Store logs here
        
        # Disable warnings if verify is False
        if not ssl_verify:
            requests.packages.urllib3.disable_warnings()
        
        self.cookies_str = cookies
        self.cookies = {}
        if cookies:
            try:
                # Basic cookie parser: "a=b; c=d" -> {'a': 'b', 'c': 'd'}
                self.cookies = dict(item.split("=", 1) for item in cookies.split("; "))
                self.session.cookies.update(self.cookies)
            except Exception as e:
                print(f"[!] Error parsing cookies: {e}")
        
        self.headers = {}
        if headers:
            for h in headers:
                try:
                    k, v = h.split(":", 1)
                    self.headers[k.strip()] = v.strip()
                    self.session.headers.update(self.headers)
                except Exception as e:
                    print(f"[!] Error parsing headers: {e}")
        
        # Add default User-Agent
        self.session.headers.update({'User-Agent': 'VULSCAN/1.0 (Authenticated Scanner)'})

        if self.use_browser:
            self._init_driver()

    def _init_driver(self):
        print("[*] Initializing headless browser (Chrome preferred for Network Logs)...")
        
        # Chrome Options (with Performance Logging)
        chrome_opts = Options()
        chrome_opts.add_argument("--headless=new")
        chrome_opts.add_argument("--no-sandbox")
        chrome_opts.add_argument("--disable-dev-shm-usage")
        if not self.ssl_verify:
            chrome_opts.add_argument("--ignore-certificate-errors")
        
        # Enable Performance Logging (CDP) & Console Logs
        chrome_opts.set_capability('goog:loggingPrefs', {'performance': 'ALL', 'browser': 'ALL'})

        try:
            # Try to use system chromedriver
            service = Service(executable_path="/usr/bin/chromedriver")
            self.driver = webdriver.Chrome(options=chrome_opts, service=service)
            return # Success
        except Exception as e:
            print(f"[*] System chromedriver failed, trying regular initialization... Error: {e}")
            try:
                self.driver = webdriver.Chrome(options=chrome_opts)
                return # Success
            except Exception as e2:
                print(f"[-] Chrome initialization failed: {e2}")

        print("[*] Chrome failed, trying Firefox (Network logs might be limited)...")
        opts = FirefoxOptions()
        opts.add_argument("--headless")
        try:
            service = FirefoxService(executable_path="/usr/bin/geckodriver")
            self.driver = webdriver.Firefox(options=opts, service=service)
        except Exception as e:
            print(f"[-] Firefox initialization failed: {e}")
            self.use_browser = False

    def verify_connection(self, url):
        try:
            r = self.session.get(url, timeout=10, allow_redirects=True, verify=self.ssl_verify)
            if r.status_code == 200:
                print(f"[+] Successfully connected to {url} (Status: 200)")
                # Check for redirect to login page if auth failed (common behavior)
                if "login" in r.url and "login" not in url:
                    print(f"[!] Warning: Possible redirect to login page detected: {r.url}")
                return True
            else:
                print(f"[-] Connection failed (Status: {r.status_code})")
                return False
        except Exception as e:
            print(f"[-] Request failed: {e}")
            return False

    def get(self, url):
        if self.use_browser:
            with self.driver_lock:
                return self._get_with_browser(url)
        else:
            try:
                return self.session.get(url, timeout=10, allow_redirects=True, verify=self.ssl_verify)
            except Exception as e:
                print(f"[-] GET failed for {url}: {e}")
                return None

    def _get_with_browser(self, url):
        try:
            # Pre-inject script via CDP if available (catch early execution)
            if self.live_exploit_script and self.driver.name == 'chrome':
                try:
                    with open(self.live_exploit_script, 'r') as f:
                        js_code = f.read()
                    self.driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {'source': js_code})
                    # print("[+] Pre-injected interceptor via CDP")
                except Exception as e:
                    print(f"[-] CDP Injection failed: {e}")

            self.driver.get(url)
            
            # Inject cookies if they were provided and not yet set for this domain
            if self.cookies:
                domain = urllib.parse.urlparse(url).netloc
                for name, value in self.cookies.items():
                    try:
                        self.driver.add_cookie({'name': name, 'value': value, 'domain': domain})
                    except:
                        try:
                            self.driver.add_cookie({'name': name, 'value': value})
                        except:
                            pass
                # Refresh to apply cookies if we just added them
                self.driver.get(url)

            # Wait a bit for JS to execute
            time.sleep(3)

            # Live Exploit / Interceptor Injection
            if self.live_exploit_script:
                self.inject_script(self.live_exploit_script)
                time.sleep(2) # Wait for script to run/intercept
                self.read_console_logs()
            
            # Create a mock response object that looks like requests.Response
            class MockResponse:
                def __init__(self, text, url, headers):
                    self.text = text
                    self.url = url
                    self.status_code = 200 
                    self.headers = headers

            return MockResponse(self.driver.page_source, self.driver.current_url, {'Content-Type': 'text/html'})
        except Exception as e:
            print(f"[-] Browser GET failed for {url}: {e}")
            return None

    def inject_script(self, script_path):
        if not self.use_browser or not self.driver:
            return
        try:
            with open(script_path, 'r') as f:
                js_code = f.read()
            self.driver.execute_script(js_code)
            # print(f"[+] Injected script from {script_path}")
        except Exception as e:
            print(f"[-] Failed to inject script: {e}")

    def read_console_logs(self):
        new_findings = []
        if not self.use_browser or not self.driver:
            return new_findings
        
        try:
            logs = self.driver.get_log('browser')
            for entry in logs:
                msg = entry.get('message', '')
                if any(x in msg for x in ["AES CALL INTERCEPTED", "FOUND GLOBAL", "WEB CRYPTO", "VULSCAN", "🌐", "🛠", "📦", "🔓"]):
                    new_findings.append(msg)
                    self.captured_logs.append(msg)
                    print(f"[*] LIVE LOG: {msg}")
                elif any(x in msg for x in ["KEY (hex)", "KEY (ascii)", "KEY (utf8)", "IV (hex)", "IV (ascii)"]):
                    new_findings.append(msg)
                    self.captured_logs.append(msg)
                    print(f"[🔑] {msg}")
        except Exception as e:
            # Firefox doesn't support get_log('browser') easily via Selenium
            pass
        return new_findings

    def get_network_logs(self):
        """
        Retrieves Network tab logs (XHR/Fetch responses) using Chrome DevTools Protocol.
        Returns a dict of {url: content} for interesting background requests.
        """
        background_content = {}
        if not self.driver or self.driver.name != 'chrome':
            return background_content

        with self.driver_lock:
            try:
                logs = self.driver.get_log('performance')
                for entry in logs:
                    try:
                        message = json.loads(entry['message'])['message']
                        if message['method'] == 'Network.responseReceived':
                            params = message['params']
                            response = params.get('response', {})
                            url = response.get('url', '')
                            mime_type = response.get('mimeType', '').lower()
                            request_id = params.get('requestId')
                            
                            # Filter for interesting content types (JSON, JS, XML, Text)
                            if 'json' in mime_type or 'javascript' in mime_type or 'xml' in mime_type or 'text' in mime_type:
                                try:
                                    # Fetch response body via CDP
                                    body_data = self.driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id})
                                    content = body_data.get('body', '')
                                    if content:
                                        background_content[url] = content
                                except Exception:
                                    # Body might not be available or request failed
                                    pass
                    except Exception:
                        pass
            except Exception as e:
                print(f"[!] Error retrieving network logs: {e}")
            
            return background_content

    def close(self):
        if self.driver:
            with self.driver_lock:
                self.driver.quit()
