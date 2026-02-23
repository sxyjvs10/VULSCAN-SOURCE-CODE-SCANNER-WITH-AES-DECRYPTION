import subprocess
import os
import re

class KeyForge:
    def __init__(self, crypto_js_path="crypto-js.min.js"):
        self.crypto_js_path = os.path.abspath(crypto_js_path)

    def decrypt(self, kek, blob):
        """
        Attempts to decrypt using the KeyForge algorithm via Node.js
        """
        if not os.path.exists(self.crypto_js_path):
            return None

        js_script = f"""
        const fs = require('fs');
        const CryptoJS = require('./{os.path.basename(self.crypto_js_path)}');

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
                // Step 1: Decode KEK (atob)
                let a1 = safeAtob(kek);
                if (!a1) return "Error: KEK decode failed";

                // Step 2: Decode KEK again (atob^2) to get password
                let password = safeAtob(a1) || a1;

                // Step 3: Decrypt Blob using Password
                let decrypted = CryptoJS.AES.decrypt(blob, password).toString(CryptoJS.enc.Utf8);
                if (!decrypted) return "Error: Blob decryption failed";

                // Step 4: Check if binary CSV
                let binParts = decrypted.split(',').map(s => s.trim()).filter(Boolean);
                let isBinCSV = binParts.length > 4 && /^[01]{{6,8}}$/.test(binParts[0]);
                
                let backStr = decrypted;
                if (isBinCSV) {{
                    backStr = binParts.map(b => String.fromCharCode(parseInt(b, 2))).join('');
                }}

                // Step 5: Triple Atob Chain
                let b1 = safeAtob(backStr);
                if (!b1) return "Error: Final decode step 1 failed";
                
                let b2 = safeAtob(b1);
                if (!b2) return "Error: Final decode step 2 failed";

                let finalKey = safeAtob(b2);
                
                // If the last step fails, return b2 (some variations stop at double atob)
                return finalKey || b2;

            }} catch (e) {{
                return "Error: " + e.message;
            }}
        }}

        console.log(decrypt());
        """

        try:
            # Create temp JS file
            temp_js = "temp_keyforge.js"
            with open(temp_js, "w") as f:
                f.write(js_script)

            # Run with node
            result = subprocess.run(["node", temp_js], capture_output=True, text=True, timeout=5)
            os.remove(temp_js)

            if result.returncode == 0:
                output = result.stdout.strip()
                return output # Return output even if it is an error for debugging
            return f"Error: Node process failed with code {result.returncode} - {result.stderr}"
        except Exception as e:
            return f"Error: Exception {str(e)}"
