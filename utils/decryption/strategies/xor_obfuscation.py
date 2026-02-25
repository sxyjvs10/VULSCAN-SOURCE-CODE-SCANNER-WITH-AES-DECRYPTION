import re
import base64
import requests
import json
from urllib.parse import urljoin
from .base import DecryptionStrategy

class XORObfuscationStrategy(DecryptionStrategy):
    """
    Detects simple XOR-based string decryption routines often used in 
    client-side obfuscation (e.g., malware, simple protection scripts).
    
    Also attempts to actively fetch and decrypt keys if an endpoint and 
    headers are discovered (Active Probe).
    """

    def detect_and_decrypt(self, content, url):
        findings = []
        xor_key = None

        # 1. Detect the XOR operation pattern
        xor_op_pattern = r'\.charCodeAt\s*\([^)]*\)\s*\^\s*([a-zA-Z0-9_$]+)\.charCodeAt'
        matches = re.finditer(xor_op_pattern, content)
        seen_keys = set()

        for match in matches:
            key_var_name = match.group(1)
            if key_var_name in seen_keys: continue
            seen_keys.add(key_var_name)

            # Find definition: const key = 'val';
            key_def_pattern = r'(?:const|let|var)\s+' + re.escape(key_var_name) + r'\s*=\s*([\'"])(.*?)\1'
            key_match = re.search(key_def_pattern, content)

            if key_match:
                extracted_key = key_match.group(2)
                if len(extracted_key) < 3: continue

                xor_key = extracted_key # Store for active probe
                snippet = content[max(0, match.start() - 100):min(len(content), match.end() + 100)]
                
                findings.append({
                    'url': url,
                    'type': 'HARDCODED_XOR_KEY',
                    'severity': 'HIGH',
                    'description': f'Hardcoded XOR key "{extracted_key}" found in decryption logic.',
                    'remediation': 'Do not hardcode encryption keys in client-side code.',
                    'match': extracted_key,
                    'context': snippet.strip(),
                    'decoded_value': extracted_key,
                    'line': content[:match.start()].count('\n') + 1,
                    'source': 'STATIC'
                })

        # 2. Active Probe Logic
        # If we found an XOR key, look for a fetch endpoint to use it on.
        if xor_key:
            # Look for endpoint: fetch(baseUrl + '/Path/To/Key')
            # Regex captures the string path.
            fetch_pattern = r'fetch\s*\(\s*(?:[a-zA-Z0-9_$.]+\s*\+\s*)?[\'"]([^\'"]*Key[^\'"]*)[\'"]'
            endpoint_match = re.search(fetch_pattern, content, re.IGNORECASE)
            
            # Look for API Key header
            header_pattern = r'[\'"](X-API-Key)[\'"]\s*:\s*[\'"]([^\'"]+)[\'"]'
            header_match = re.search(header_pattern, content, re.IGNORECASE)

            if endpoint_match:
                endpoint_path_raw = endpoint_match.group(1)
                
                # Extract Base URL if present in the script
                base_url_match = re.search(r'this\.baseUrl\s*=\s*[\'"]([^\'"]+)[\'"]', content)
                effective_base = base_url_match.group(1) if base_url_match else url

                # Try likely combinations
                potential_urls = set()
                potential_urls.add(urljoin(effective_base, endpoint_path_raw))
                if base_url_match:
                     potential_urls.add(effective_base.rstrip('/') + '/' + endpoint_path_raw.lstrip('/'))
                potential_urls.add(urljoin(url, endpoint_path_raw))
                potential_urls.add(urljoin(url, endpoint_path_raw.lstrip('/')))
                
                headers = {'Content-Type': 'application/json; charset=utf-8'}
                if header_match:
                    headers[header_match.group(1)] = header_match.group(2)
                    findings.append({
                        'url': url,
                        'type': 'HARDCODED_API_HEADER',
                        'severity': 'MEDIUM',
                        'description': f'Hardcoded API Header found: {header_match.group(1)}',
                        'match': header_match.group(2),
                        'context': header_match.group(0),
                        'line': content[:header_match.start()].count('\n') + 1,
                        'source': 'STATIC'
                    })

                # Try to fetch
                for target_url in potential_urls:
                    try:
                        # print(f"[*] Probing detected key endpoint: {target_url}")
                        resp = requests.post(target_url, headers=headers, json={}, timeout=5, verify=False)
                        if resp.status_code == 200:
                            data = resp.json()
                            # Traverse simple d.key structure (ASP.NET common) or just key
                            encrypted_blob = None
                            if 'd' in data and isinstance(data['d'], dict) and 'key' in data['d']:
                                encrypted_blob = data['d']['key']
                            elif 'key' in data:
                                encrypted_blob = data['key']
                            
                            if encrypted_blob:
                                # Attempt Decrypt
                                try:
                                    decoded_blob = base64.b64decode(encrypted_blob).decode('latin1') # decoding as bytes-string
                                    decrypted_chars = []
                                    for i, char in enumerate(decoded_blob):
                                        decrypted_char = chr(ord(char) ^ ord(xor_key[i % len(xor_key)]))
                                        decrypted_chars.append(decrypted_char)
                                    decrypted_key = "".join(decrypted_chars)

                                    findings.append({
                                        'url': target_url,
                                        'type': 'EXPOSED_MAIN_KEY',
                                        'severity': 'CRITICAL',
                                        'description': 'Successfully intercepted and decrypted the Master Key via active probing.',
                                        'remediation': 'Revoke this key immediately. It is exposed to any visitor.',
                                        'match': decrypted_key,
                                        'context': f"Endpoint: {target_url} | XOR Key: {xor_key}",
                                        'decoded_value': decrypted_key,
                                        'line': 0,
                                        'source': 'DYNAMIC_PROBE'
                                    })
                                    break # Stop trying other URLs if success
                                except Exception as e:
                                    pass # Decryption failed
                    except Exception as e:
                        pass # Request failed

        return findings
