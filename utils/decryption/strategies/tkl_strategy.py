import re
from .base import DecryptionStrategy

class TklStrategy(DecryptionStrategy):
    def detect_and_decrypt(self, content, url):
        findings = []
        
        # The known parts of the Tkl key in Juice Shop
        # They are usually split in the source code
        part1 = "96297ixpfRh"
        part2 = "21ETXDcD"
        part3 = "ZMcbh"
        
        # Check if all parts exist in the content
        if part1 in content and part2 in content and part3 in content:
            # Reconstruct the key
            combined = part1 + part2 + part3
            
            findings.append({
                'url': url,
                'type': 'TKL_OBFUSCATED_KEY',
                'severity': 'CRITICAL',
                'description': 'Detected "Tkl" pattern (split string obfuscation) commonly used to hide AES keys in Juice Shop.',
                'remediation': 'Store keys securely on the server side, not in client-side code.',
                'match': f"Parts found: {part1}, {part2}, {part3}",
                'context': f"Reconstructed Key: {combined}",
                'line': content.count('\n', 0, content.find(part1)) + 1,
                'decoded_value': combined
            })
            
        return findings
