import re
import os
import subprocess
from .base import DecryptionStrategy

class KeyForgeStrategy(DecryptionStrategy):
    def __init__(self, crypto_js_path="crypto-js"):
        self.crypto_js_path = crypto_js_path

    def detect_and_decrypt(self, content, url):
        findings = []
        
        # Regex to catch 'kek =' even in comma lists
        kek_match = re.search(r"\bkek\s*=\s*['\"]([A-Za-z0-9+/=_ -]{20,})['\"]", content)
        
        # 1. Try specific variable assignment
        blob_match = re.search(r"\bencryptedAutoIncrement\s*=\s*['\"]([A-Za-z0-9+/=_ -]{40,})['\"]", content)
        
        # 2. Fallback: Look for any "Salted__" (U2FsdGVkX1) string literal in the code
        if not blob_match:
            blob_match = re.search(r"['\"](U2FsdGVkX1[A-Za-z0-9+/=_ -]{40,})['\"]", content)

        if kek_match and blob_match:
            kek_val = kek_match.group(1)
            blob_val = blob_match.group(1)
            
            decrypted_key = self._run_node_script(kek_val, blob_val)
            
            if decrypted_key and not decrypted_key.startswith("Error:"):
                findings.append({
                    'url': url,
                    'type': 'KEYFORGE_DECRYPTED_SECRET',
                    'severity': 'CRITICAL',
                    'description': 'Successfully decrypted hidden client-side AES key using KeyForge algorithm.',
                    'remediation': 'Revoke this key immediately. Do not hide secrets in client-side code.',
                    'match': f"kek={kek_val[:10]}... blob={blob_val[:10]}...",
                    'context': f"Decrypted Key: {decrypted_key}",
                    'line': content.count('\n', 0, kek_match.start()) + 1,
                    'decoded_value': decrypted_key
                })
        return findings

    def _run_node_script(self, kek, blob):
        js_script = f"""
        const CryptoJS = require('{self.crypto_js_path}');

        const kek = "{kek}";
        const blob = "{blob}";

        function safeAtob(str) {{
            try {{
                return Buffer.from(str, 'base64').toString('binary');
            }} catch (e) {{
                return null;
            }}
        }}

        function decrypt() {{
            try {{
                let a1 = safeAtob(kek);
                if (!a1) return "Error: KEK decode failed";
                let password = safeAtob(a1) || a1;
                let decrypted = CryptoJS.AES.decrypt(blob, password).toString(CryptoJS.enc.Utf8);
                if (!decrypted) return "Error: Blob decryption failed";
                
                let binParts = decrypted.split(',').map(s => s.trim()).filter(Boolean);
                let isBinCSV = binParts.length > 4 && /^[01]{{6,8}}$/.test(binParts[0]);
                let backStr = decrypted;
                if (isBinCSV) {{
                    backStr = binParts.map(b => String.fromCharCode(parseInt(b, 2))).join('');
                }}
                
                let b1 = safeAtob(backStr);
                if (!b1) return "Error: Final decode step 1 failed";
                let b2 = safeAtob(b1);
                if (!b2) return "Error: Final decode step 2 failed";
                let finalKey = safeAtob(b2);
                return finalKey || b2;
            }} catch (e) {{
                return "Error: " + e.message;
            }}
        }}
        console.log(decrypt());
        """
        try:
            temp_js = "temp_kf_strat.js"
            with open(temp_js, "w") as f: f.write(js_script)
            result = subprocess.run(["node", temp_js], capture_output=True, text=True, timeout=5)
            os.remove(temp_js)
            if result.returncode == 0:
                return result.stdout.strip()
            return f"Error: Node failed - {result.stderr}"
        except Exception as e:
            return f"Error: {e}"
