import re
import base64
import binascii
from .base import DecryptionStrategy

class Base64HexStrategy(DecryptionStrategy):
    def detect_and_decrypt(self, content, url):
        findings = []
        # Look for high-entropy strings or common variable assignments
        # This regex looks for strings assigned to variables that look like base64 or hex
        # It's a bit heuristic.
        
        # Regex for potential secrets (assignments)
        regex = r"\b(?:key|secret|token|password|auth|api_key)\s*[:=]\s*['\"]([A-Za-z0-9+/=_ -]{20,}|[A-Fa-f0-9]{32,})['\"]"
        
        matches = re.finditer(regex, content, re.IGNORECASE)
        for match in matches:
            val = match.group(1)
            decoded = self._decode_value(val)
            if decoded:
                findings.append({
                    'url': url,
                    'type': 'DECODED_SECRET',
                    'severity': 'HIGH',
                    'description': 'Potential secret decoded from source code.',
                    'remediation': 'Check if this value is sensitive.',
                    'match': match.group(0),
                    'context': f"Decoded: {decoded}",
                    'line': content[:match.start()].count('\n') + 1,
                    'decoded_value': decoded
                })
        return findings

    def _decode_value(self, value):
        clean_value = value.strip("'\"")
        results = []
        
        # 1. Base64
        try:
            # Normalize for Base64 (URL-safe and weird variants)
            b64_val = clean_value.replace('-', '+').replace('_', '/')
            # Pad if needed
            b64_val += '=' * ((4 - len(b64_val) % 4) % 4)
            
            b64_decoded = base64.b64decode(b64_val)
            try:
                text = b64_decoded.decode('utf-8')
                if any(c.isalnum() for c in text) and len(text) > 4:
                    results.append(f"Base64: {text}")
                    # Try double Base64
                    try:
                        double_b64 = base64.b64decode(text).decode('utf-8')
                        if any(c.isalnum() for c in double_b64):
                            results.append(f"Double Base64: {double_b64}")
                    except: pass
            except:
                if len(b64_decoded) > 0:
                    results.append(f"Base64 (Hex): {b64_decoded.hex()}")
        except: pass
            
        # 2. Hex
        try:
            if re.match(r'^[0-9a-fA-F]+$', clean_value):
                hex_decoded = binascii.unhexlify(clean_value)
                try:
                    text = hex_decoded.decode('utf-8')
                    if any(c.isalnum() for c in text) and len(text) > 4:
                        results.append(f"Hex: {text}")
                except:
                    pass
        except: pass
            
        return " | ".join(results) if results else None
