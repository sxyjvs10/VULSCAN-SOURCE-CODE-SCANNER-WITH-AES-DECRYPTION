import re
import base64
from .base import DecryptionStrategy

class BinaryChainStrategy(DecryptionStrategy):
    """
    Handles secrets encoded as Base64 -> Binary CSV -> Multiple Base64 layers.
    Example: atob(atob(atob(bin2String(atob(data)))))
    """
    def detect_and_decrypt(self, content, url):
        findings = []

        # 1. Look for potential encoded strings (long base64-like literals)
        # We look for strings that are at least 40 chars long and look like Base64.
        # We check both single and double quoted strings.
        # Including - and _ for Base64URL variants.
        potential_strings = re.findall(r"'([A-Za-z0-9+/=_ -]{40,})'", content)
        potential_strings += re.findall(r'"([A-Za-z0-9+/=_ -]{40,})"', content)

        for raw_val in potential_strings:
            decrypted = self._attempt_binary_chain(raw_val)
            if decrypted and len(decrypted) > 4:
                # To avoid false positives, we check if the result is alphanumeric
                if any(c.isalnum() for c in decrypted):
                    findings.append({
                        'url': url,
                        'type': 'BINARY_CHAIN_DECRYPTED_SECRET',
                        'severity': 'CRITICAL',
                        'description': 'Detected and decrypted a multi-layer binary/base64 encoded secret.',
                        'remediation': 'Secrets should not be stored in client-side code, even if obfuscated.',
                        'match': f"data={raw_val[:15]}...",
                        'context': f"Decrypted Result: {decrypted}",
                        'line': content.count('\n', 0, content.find(raw_val)) + 1,
                        'decoded_value': decrypted
                    })
        return findings

    def _attempt_binary_chain(self, value):
        try:
            # Normalize Base64 (handle URL-safe variants and weird ones with both)
            clean_value = value.replace('-', '+').replace('_', '/')
            # Pad if needed
            clean_value += '=' * ((4 - len(clean_value) % 4) % 4)

            # Layer 1: First atob
            s1 = base64.b64decode(clean_value).decode('utf-8', errors='ignore')

            # Remove potential surrounding quotes
            s1 = s1.strip("'\"")

            # Check if it looks like binary CSV: "1010110,1000111,..."
            if not re.match(r'^[01]{1,8}(,[01]{1,8})*$', s1):
                return None

            # Step 2: Convert binary CSV to characters
            binary_parts = s1.split(',')
            s2 = "".join([chr(int(b, 2)) for b in binary_parts])

            # Step 3: Repeatedly atob (up to 4 more times as per the strategy description)
            current = s2
            last_valid = s2

            # Step 3: Repeatedly atob (up to 4 more times as per the strategy description)
            current = s2
            last_valid = s2

            for _ in range(4):
                try:
                    # Clean the string for atob (handle - and _)
                    clean_current = current.replace('-', '+').replace('_', '/')
                    # If current contains characters that are NOT valid Base64, it's probably the secret
                    if re.search(r'[^A-Za-z0-9+/=]', clean_current):
                        break

                    # Pad if needed
                    clean_current += '=' * ((4 - len(clean_current) % 4) % 4)
                    
                    decoded_bytes = base64.b64decode(clean_current)
                    decoded = decoded_bytes.decode('utf-8', errors='ignore')

                    # If it's still looking like base64 or has printable content, continue
                    if any(c.isalnum() for c in decoded):
                        current = decoded
                        last_valid = decoded
                    else:
                        break
                except Exception:
                    break

            return last_valid

        except Exception:
            return None