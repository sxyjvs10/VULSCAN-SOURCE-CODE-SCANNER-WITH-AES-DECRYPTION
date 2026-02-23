from .strategies.base import DecryptionStrategy
from .strategies.base64_hex import Base64HexStrategy
from .strategies.keyforge_strategy import KeyForgeStrategy
from .strategies.binary_chain import BinaryChainStrategy

class DecryptionManager:
    def __init__(self):
        self.strategies = []
        self._register_strategies()

    def _register_strategies(self):
        # Add strategies here. Order matters (most specific to least specific).
        self.strategies.append(KeyForgeStrategy())
        self.strategies.append(BinaryChainStrategy())
        self.strategies.append(Base64HexStrategy())

    def run(self, content, url):
        """
        Runs all registered strategies on the content.
        Returns a flat list of all findings.
        """
        all_findings = []
        for strategy in self.strategies:
            try:
                findings = strategy.detect_and_decrypt(content, url)
                if findings:
                    all_findings.extend(findings)
            except Exception as e:
                # Log error but don't stop other strategies
                # print(f"[-] Decryption strategy {strategy.__class__.__name__} failed: {e}")
                pass
        return all_findings
