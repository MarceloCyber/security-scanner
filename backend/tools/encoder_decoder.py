"""
Encoder/Decoder Utilities
Various encoding and decoding functions for security testing
"""
import base64
import urllib.parse
import html
import hashlib
import binascii
from typing import Dict, Any
import json


class EncoderDecoder:
    """Encoding and decoding utilities"""
    
    def encode(self, text: str, encoding_type: str) -> Dict[str, Any]:
        """
        Encode text with specified encoding
        
        Args:
            text: Text to encode
            encoding_type: Type of encoding (base64, url, html, hex, etc.)
        
        Returns:
            Dict with encoded result and metadata
        """
        encoders = {
            "base64": self._base64_encode,
            "url": self._url_encode,
            "html": self._html_encode,
            "hex": self._hex_encode,
            "binary": self._binary_encode,
            "rot13": self._rot13_encode,
            "unicode": self._unicode_encode,
            "double_url": self._double_url_encode,
        }
        
        if encoding_type not in encoders:
            raise ValueError(f"Encoding '{encoding_type}' not supported. Available: {list(encoders.keys())}")
        
        return encoders[encoding_type](text)
    
    def decode(self, text: str, encoding_type: str) -> Dict[str, Any]:
        """
        Decode text with specified encoding
        
        Args:
            text: Text to decode
            encoding_type: Type of encoding (base64, url, html, hex, etc.)
        
        Returns:
            Dict with decoded result and metadata
        """
        decoders = {
            "base64": self._base64_decode,
            "url": self._url_decode,
            "html": self._html_decode,
            "hex": self._hex_decode,
            "binary": self._binary_decode,
            "rot13": self._rot13_decode,
            "unicode": self._unicode_decode,
        }
        
        if encoding_type not in decoders:
            raise ValueError(f"Decoding '{encoding_type}' not supported. Available: {list(decoders.keys())}")
        
        return decoders[encoding_type](text)
    
    def hash_text(self, text: str, hash_type: str) -> Dict[str, Any]:
        """
        Generate hash of text
        
        Args:
            text: Text to hash
            hash_type: Type of hash (md5, sha1, sha256, sha512)
        
        Returns:
            Dict with hash result and metadata
        """
        hashers = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
        }
        
        if hash_type not in hashers:
            raise ValueError(f"Hash type '{hash_type}' not supported. Available: {list(hashers.keys())}")
        
        hasher = hashers[hash_type]
        hash_result = hasher(text.encode()).hexdigest()
        
        return {
            "original": text,
            "hash": hash_result,
            "hash_type": hash_type,
            "length": len(hash_result)
        }
    
    # Encoding methods
    def _base64_encode(self, text: str) -> Dict[str, Any]:
        encoded = base64.b64encode(text.encode()).decode()
        return {
            "original": text,
            "encoded": encoded,
            "encoding": "base64",
            "length": len(encoded)
        }
    
    def _url_encode(self, text: str) -> Dict[str, Any]:
        encoded = urllib.parse.quote(text)
        return {
            "original": text,
            "encoded": encoded,
            "encoding": "url",
            "length": len(encoded)
        }
    
    def _html_encode(self, text: str) -> Dict[str, Any]:
        encoded = html.escape(text)
        return {
            "original": text,
            "encoded": encoded,
            "encoding": "html",
            "length": len(encoded)
        }
    
    def _hex_encode(self, text: str) -> Dict[str, Any]:
        encoded = binascii.hexlify(text.encode()).decode()
        return {
            "original": text,
            "encoded": encoded,
            "encoding": "hex",
            "length": len(encoded)
        }
    
    def _binary_encode(self, text: str) -> Dict[str, Any]:
        encoded = ' '.join(format(ord(c), '08b') for c in text)
        return {
            "original": text,
            "encoded": encoded,
            "encoding": "binary",
            "length": len(encoded)
        }
    
    def _rot13_encode(self, text: str) -> Dict[str, Any]:
        encoded = text.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        ))
        return {
            "original": text,
            "encoded": encoded,
            "encoding": "rot13",
            "length": len(encoded)
        }
    
    def _unicode_encode(self, text: str) -> Dict[str, Any]:
        encoded = ''.join(f'\\u{ord(c):04x}' for c in text)
        return {
            "original": text,
            "encoded": encoded,
            "encoding": "unicode",
            "length": len(encoded)
        }
    
    def _double_url_encode(self, text: str) -> Dict[str, Any]:
        encoded = urllib.parse.quote(urllib.parse.quote(text))
        return {
            "original": text,
            "encoded": encoded,
            "encoding": "double_url",
            "length": len(encoded)
        }
    
    # Decoding methods
    def _base64_decode(self, text: str) -> Dict[str, Any]:
        try:
            decoded = base64.b64decode(text).decode()
            return {
                "encoded": text,
                "decoded": decoded,
                "encoding": "base64",
                "success": True
            }
        except Exception as e:
            return {
                "encoded": text,
                "decoded": None,
                "encoding": "base64",
                "success": False,
                "error": str(e)
            }
    
    def _url_decode(self, text: str) -> Dict[str, Any]:
        decoded = urllib.parse.unquote(text)
        return {
            "encoded": text,
            "decoded": decoded,
            "encoding": "url",
            "success": True
        }
    
    def _html_decode(self, text: str) -> Dict[str, Any]:
        decoded = html.unescape(text)
        return {
            "encoded": text,
            "decoded": decoded,
            "encoding": "html",
            "success": True
        }
    
    def _hex_decode(self, text: str) -> Dict[str, Any]:
        try:
            decoded = binascii.unhexlify(text.replace(' ', '')).decode()
            return {
                "encoded": text,
                "decoded": decoded,
                "encoding": "hex",
                "success": True
            }
        except Exception as e:
            return {
                "encoded": text,
                "decoded": None,
                "encoding": "hex",
                "success": False,
                "error": str(e)
            }
    
    def _binary_decode(self, text: str) -> Dict[str, Any]:
        try:
            binary_values = text.split()
            decoded = ''.join(chr(int(b, 2)) for b in binary_values)
            return {
                "encoded": text,
                "decoded": decoded,
                "encoding": "binary",
                "success": True
            }
        except Exception as e:
            return {
                "encoded": text,
                "decoded": None,
                "encoding": "binary",
                "success": False,
                "error": str(e)
            }
    
    def _rot13_decode(self, text: str) -> Dict[str, Any]:
        # ROT13 is its own inverse
        return self._rot13_encode(text)
    
    def _unicode_decode(self, text: str) -> Dict[str, Any]:
        try:
            # Handle \uXXXX format
            decoded = text.encode().decode('unicode-escape')
            return {
                "encoded": text,
                "decoded": decoded,
                "encoding": "unicode",
                "success": True
            }
        except Exception as e:
            return {
                "encoded": text,
                "decoded": None,
                "encoding": "unicode",
                "success": False,
                "error": str(e)
            }
    
    def list_encodings(self) -> Dict[str, list]:
        """List all available encodings"""
        return {
            "encodings": [
                {"id": "base64", "name": "Base64", "description": "Standard Base64 encoding"},
                {"id": "url", "name": "URL Encoding", "description": "Percent-encoding for URLs"},
                {"id": "html", "name": "HTML Entities", "description": "HTML entity encoding"},
                {"id": "hex", "name": "Hexadecimal", "description": "Hex representation"},
                {"id": "binary", "name": "Binary", "description": "Binary representation"},
                {"id": "rot13", "name": "ROT13", "description": "Caesar cipher with 13 shift"},
                {"id": "unicode", "name": "Unicode Escape", "description": "Unicode escape sequences"},
                {"id": "double_url", "name": "Double URL", "description": "URL encoding applied twice"},
            ],
            "hashes": [
                {"id": "md5", "name": "MD5", "description": "128-bit hash (weak)"},
                {"id": "sha1", "name": "SHA-1", "description": "160-bit hash (deprecated)"},
                {"id": "sha256", "name": "SHA-256", "description": "256-bit hash (recommended)"},
                {"id": "sha512", "name": "SHA-512", "description": "512-bit hash (strong)"},
            ]
        }
