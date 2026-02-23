from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time
import requests

class LoginManager:
    def __init__(self, login_url, username, password, headless=True):
        self.login_url = login_url
        self.username = username
        self.password = password
        self.headless = headless
        self.cookies = {}

    def login(self):
        print("[*] Initiating Auto-Login using Selenium...")
        
        chrome_options = Options()
        if self.headless:
            chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--ignore-certificate-errors")
        
        # Adjust binary location if necessary, assuming default chromium
        chrome_options.binary_location = "/usr/bin/chromium"

        try:
            # We will use webdriver_manager to get the driver
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            
            print(f"[*] Navigating to {self.login_url}...")
            driver.get(self.login_url)
            
            # Wait for the username field (based on the previous grep, ID is likely 'txtempid')
            print("[*] Waiting for login fields...")
            try:
                username_field = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.ID, "txtempid"))
                )
                password_field = driver.find_element(By.ID, "txtpassword")
                
                print("[*] Entering credentials...")
                username_field.clear()
                username_field.send_keys(self.username)
                password_field.clear()
                password_field.send_keys(self.password)
                
                # Handle Captcha if present? 
                # The previous JS showed a captcha implementation.
                # If there's a captcha, automated login will fail without a solver.
                # JS: _login.GenerateCaptcha(); ... inputcap === ""
                # It's a client-side captcha: $('#captcha').text(_login.generatedCaptcha);
                # So we can read the captcha text and fill it!
                
                try:
                    captcha_element = driver.find_element(By.ID, "captcha")
                    captcha_text = captcha_element.text
                    print(f"[*] Detected Client-Side Captcha: {captcha_text}")
                    
                    captcha_input = driver.find_element(By.ID, "captchavalidate")
                    captcha_input.clear()
                    captcha_input.send_keys(captcha_text)
                except Exception as e:
                    print(f"[*] No captcha detected or error handling it: {e}")

                # Login Button
                login_btn = driver.find_element(By.ID, "btnlogin")
                login_btn.click()
                
                print("[*] Submitting login form...")
                
                # Wait for navigation or success
                # Success usually redirects to HOME_URL or changes UI
                time.sleep(5) # Simple wait for redirect/processing
                
                # Extract cookies
                selenium_cookies = driver.get_cookies()
                for cookie in selenium_cookies:
                    self.cookies[cookie['name']] = cookie['value']
                
                print(f"[+] Login successful? Extracted {len(self.cookies)} cookies.")
                
            except Exception as e:
                print(f"[-] Error during login interaction: {e}")
            finally:
                driver.quit()
                
        except Exception as e:
            print(f"[-] Selenium Error: {e}")
            
        return self.cookies

    def get_cookie_string(self):
        return "; ".join([f"{k}={v}" for k, v in self.cookies.items()])
