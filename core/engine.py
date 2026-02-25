import re
import urllib.parse
from utils.component_checker import ComponentChecker
from utils.decryption.manager import DecryptionManager

class Analyzer:
    def __init__(self, vuln_db=None):
        self.findings = []
        self.vuln_db = vuln_db
        self.component_checker = None
        if vuln_db:
            self.component_checker = ComponentChecker(vuln_db)
        
        self.decryption_manager = DecryptionManager()
        
        self.patterns = {
            'API_KEY_AWS': {
                'pattern': r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])', # Simplified, usually AKIA...
                'regex': r'AKIA[0-9A-Z]{16}',
                'severity': 'HIGH',
                'description': 'AWS Access Key ID detected.',
                'remediation': 'Revoke the key and use IAM roles.'
            },
            'API_KEY_GOOGLE': {
                'regex': r'AIza[0-9A-Za-z-_]{35}',
                'severity': 'HIGH',
                'description': 'Google API Key detected.',
                'remediation': 'Restrict the key or use backend proxy.'
            },
            'PRIVATE_KEY': {
                'regex': r'-----BEGIN PRIVATE KEY-----',
                'severity': 'CRITICAL',
                'description': 'Private Key detected.',
                'remediation': 'Rotate keys immediately and store secrets securely.'
            },
            'DANGEROUS_JS_EVAL': {
                'regex': r'\beval\(',
                'severity': 'HIGH',
                'description': 'Use of eval() detected.',
                'remediation': 'Avoid eval(); use JSON.parse() or safer alternatives.'
            },
            'DANGEROUS_JS_DOCWRITE': {
                'regex': r'document\.write\(',
                'severity': 'MEDIUM',
                'description': 'Use of document.write() detected.',
                'remediation': 'Use DOM manipulation methods like appendChild().'
            },
            'DANGEROUS_JS_INNERHTML': {
                'regex': r'\.innerHTML\s*=',
                'severity': 'MEDIUM',
                'description': 'Unsafe innerHTML assignment.',
                'remediation': 'Use textContent or sanitize input.'
            },
            'SENSITIVE_COMMENT': {
                'regex': r'(TODO|FIXME|HACK|XXX):',
                'severity': 'INFO',
                'description': 'Developer comment detected.',
                'remediation': 'Review comments for sensitive info before deployment.'
            },
            'PASSWORD_FIELD': {
                'regex': r'type=["\']password["\']',
                'severity': 'LOW',
                'description': 'Password field detected (Info).',
                'remediation': 'Ensure forms are served over HTTPS.'
            },
            'POTENTIAL_XSS_SINK': {
                'regex': r'location\.hash|location\.search|document\.cookie',
                'severity': 'MEDIUM',
                'description': 'Potential XSS sink detected.',
                'remediation': 'Validate and sanitize data from these sources.'
            },
            'CUSTOM_KEY_SYMBOLS': {
                'regex': r'\$785%\$#\*\*5#@!7\^#',
                'severity': 'HIGH',
                'description': 'Custom Pattern Symbols detected.',
                'remediation': 'Investigate this custom secret format.'
            },
            'CUSTOM_HARDCODED_SECRETS': {
                'regex': r'([37]x!A%[DS]\*[IG]-[\w@#$%^&*!]{6,8})|(&a!@0\(l%\+0YU\*\^4g)|(LD@8RG#3SEZ)|(3337373832353434326134373264346236313530363435333637353632343430)',
                'severity': 'CRITICAL',
                'description': 'Known custom hardcoded secret detected.',
                'remediation': 'These patterns match known secret keys. Rotate immediately.'
            },
            'AES_OBFUSCATION_LOOP': {
                'regex': r'while\s*\(\s*!!\[\]\s*\)\s*\{.*?push.*shift',
                'severity': 'HIGH',
                'description': 'Obfuscated array rotation loop detected (common in malware/packers).',
                'remediation': 'Deobfuscate and analyze the code logic.'
            },
            'HARDCODED_KEK': {
                'regex': r'UlVGbk1tbHVkR0kyYm5wUFZYVXlTMEk9',
                'severity': 'HIGH',
                'description': 'Hardcoded Key Encryption Key (KEK) detected.',
                'remediation': 'Do not hardcode keys in client-side code.'
            },
            'AES_AUTO_INCREMENT': {
                'regex': r'encryptedAutoIncrement',
                'severity': 'MEDIUM',
                'description': 'Suspicious encrypted variable name detected.',
                'remediation': 'Verify the purpose of this encrypted data.'
            },
            'JWT_TOKEN': {
                'regex': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                'severity': 'HIGH',
                'description': 'Potential JWT Token detected.',
                'remediation': 'Ensure tokens are not hardcoded or leaked.'
            },
            'SLACK_TOKEN': {
                'regex': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
                'severity': 'HIGH',
                'description': 'Slack Token detected.',
                'remediation': 'Revoke token and use environment variables.'
            },
            'GOOGLE_OAUTH_ID': {
                'regex': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
                'severity': 'LOW',
                'description': 'Google OAuth Client ID detected.',
                'remediation': 'Verify if this ID is intended to be public.'
            },
            'SENSITIVE_API_PATH': {
                'regex': r'/(api|v1|v2|graphql|swagger|admin)/',
                'severity': 'INFO',
                'description': 'Sensitive API or Admin path detected.',
                'remediation': 'Ensure endpoints are secured.'
            },
            'SUSPICIOUS_CRYPTO_KEYWORD': {
                'regex': r'\b(crypto|encrypt|decrypt|decode|encode|cipher|key)\b',
                'severity': 'INFO',
                'description': 'Cryptography keyword detected.',
                'remediation': 'Verify strong cryptography usage.'
            },
            'HARDCODED_ENCRYPT_KEY': {
                'regex': r'\b(encryptkey|secret|token|auth_key|api_key|access_key|private_key|secret_key)\b\s*[:=]\s*["\'][\w-]{5,}["\']',
                'severity': 'HIGH',
                'description': 'Potential hardcoded secret key.',
                'remediation': 'Store secrets in environment variables.'
            },
            'GENERIC_KEY_ASSIGNMENT': {
                'regex': r'\b(k|kek|key)\b\s*[:=]\s*["\']?([\w\-]{6,})["\']?',
                'severity': 'MEDIUM',
                'description': 'Short-name key/secret assignment detected.',
                'remediation': 'Verify if this value is sensitive.'
            },
            'CRYPTOJS_AES_ENCRYPT': {
                'regex': r'CryptoJS\.AES\.encrypt\([^,]+,\s*["\']([^"\']+)["\']',
                'severity': 'CRITICAL',
                'description': 'Hardcoded AES Key in CryptoJS detected.',
                'remediation': 'Do not hardcode keys in client-side code.'
            },
            'SUSPICIOUS_FUNC_ARG_KEY': {
                'regex': r'\(\s*[^,]+,\s*["\']([a-zA-Z0-9]{16}|[a-zA-Z0-9]{24}|[a-zA-Z0-9]{32})["\']\s*\)',
                'severity': 'HIGH',
                'description': 'Suspicious function argument (potential hardcoded key/IV).',
                'remediation': 'Verify if this string is a secret.'
            },
            'NUMERIC_PARTS_KEY_GEN': {
                'regex': r'numericParts\s*=\s*\[(\d+,\s*)+\d+\]',
                'severity': 'CRITICAL',
                'description': 'Dynamic key generation via numericParts array detected.',
                'remediation': 'Do not use predictable client-side key generation.'
            },
            'HARDCODED_KEY_VAR': {
                'regex': r'\b(aesValu|aesiv|juKu|iv)\b\s*=',
                'severity': 'HIGH',
                'description': 'Potential hardcoded/dynamic key variable assignment.',
                'remediation': 'Verify the source of this key variable.'
            },
            'BASE64_POTENTIAL_KEY': {
                'regex': r'["\'](N3[A-Za-z0-9+/]{20,60}={0,2})["\']',
                'severity': 'HIGH',
                'description': 'Suspicious Base64 string (potential encoded key starting with 7x...).',
                'remediation': 'Decode and verify if this is a hardcoded secret.'
            },
            'SENSITIVE_FILE_EXPOSURE': {
                'regex': r'([\w\-./]*\.(env|bak|bkp|old|tmp|sql|dump|db|pem|crt|key|git|svn|ds_store|zip|tar|gz|rar|7z))|\b(config\.php|wp-config\.php|settings\.py|database\.yml|appsettings\.json|web\.config|httpd\.conf|nginx\.conf|php\.ini)\b|(/etc/(passwd|shadow))',
                'severity': 'MEDIUM',
                'description': 'Reference to a potentially sensitive file/path detected.',
                'remediation': 'Ensure these files are not publicly accessible.'
            }
        }

    def scan(self, content_map, network_urls=None):
        """
        Scans extracted content (HTML/JS) for patterns and reflected inputs.
        """
        self.findings = [] # Reset findings
        network_urls = network_urls or set()
        
        for url, content in content_map.items():
            print(f"[*] Scanning {url}...")
            source = 'NETWORK' if url in network_urls else 'STATIC'
            
            # 1. Check for reflected inputs from the URL itself
            self._check_reflection(url, content, source)

            # 2. Check for known vulnerabilities in components
            if self.component_checker:
                comp_findings = self.component_checker.check(url, content)
                for f in comp_findings:
                    f['source'] = source
                self.findings.extend(comp_findings)

            # --- Advanced Decryption Strategies ---
            decryption_findings = self.decryption_manager.run(content, url)
            for f in decryption_findings:
                f['source'] = source
            self.findings.extend(decryption_findings)
            # --------------------------------------

            # 3. Check each pattern against content
            for name, data in self.patterns.items():
                pattern = data['regex']
                matches = re.finditer(pattern, content)
                for match in matches:
                    snippet = content[max(0, match.start() - 50):min(len(content), match.end() + 50)]
                    finding = {
                        'url': url,
                        'type': name,
                        'severity': data['severity'],
                        'description': data['description'],
                        'remediation': data['remediation'],
                        'match': match.group(0),
                        'context': snippet.strip(),
                        'line': content[:match.start()].count('\n') + 1,
                        'source': source
                    }
                    self.findings.append(finding)
        
        return self.findings

    def _check_reflection(self, url, content, source='STATIC'):
        """
        Checks if any query parameters from the URL are reflected in the content.
        """
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        for param, values in params.items():
            for value in values:
                if len(value) > 3:
                    # Escape value for regex if it contains special characters
                    escaped_value = re.escape(value)
                    matches = re.finditer(escaped_value, content)
                    for match in matches:
                        snippet = content[max(0, match.start() - 50):min(len(content), match.end() + 50)]
                        finding = {
                            'url': url,
                            'type': 'REFLECTED_INPUT',
                            'severity': 'MEDIUM',
                            'description': f'Input parameter "{param}" reflected in response.',
                            'remediation': 'Sanitize and encode user inputs.',
                            'match': value,
                            'context': snippet.strip(),
                            'line': content[:match.start()].count('\n') + 1,
                            'param': param,
                            'source': source
                        }
                        self.findings.append(finding)
