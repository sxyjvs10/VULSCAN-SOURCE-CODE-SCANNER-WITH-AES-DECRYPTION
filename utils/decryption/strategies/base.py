from abc import ABC, abstractmethod

class DecryptionStrategy(ABC):
    @abstractmethod
    def detect_and_decrypt(self, content, url):
        """
        Analyzes the content for specific patterns and attempts decryption.
        Returns a list of finding dictionaries or empty list.
        """
        pass
