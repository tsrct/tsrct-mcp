import json
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from utils import b64url_encode

class CryptoManager:
  def __init__(self, private_key_pem: bytes = None):
    if private_key_pem:
      self.private_key = serialization.load_pem_private_key(
        private_key_pem
        , password=None
        , backend=default_backend()
      )
    else:
      self.private_key = rsa.generate_private_key(
        public_exponent=65537
        , key_size=2048
        , backend=default_backend()
      )
    self.public_key = self.private_key.public_key()

  def get_private_key_pem(self) -> bytes:
    return self.private_key.private_bytes(
      encoding=serialization.Encoding.PEM
      , format=serialization.PrivateFormat.PKCS8
      , encryption_algorithm=serialization.NoEncryption()
    )

  def get_public_key_pem(self) -> bytes:
    return self.public_key.public_bytes(
      encoding=serialization.Encoding.PEM
      , format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

  def sign(self, data: bytes) -> str:
    """Signs data using RS256 and returns URL-safe Base64 signature."""
    signature = self.private_key.sign(
      data
      , padding.PKCS1v15()
      , hashes.SHA256()
    )
    return b64url_encode(signature)

  def encrypt(self, public_key_pem: bytes, plaintext: bytes) -> str:
    """Encrypts data using RSA-OAEP-2048 and returns URL-safe Base64 ciphertext."""
    recipient_key = serialization.load_pem_public_key(
      public_key_pem
      , backend=default_backend()
    )
    ciphertext = recipient_key.encrypt(
      plaintext
      , padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256())
        , algorithm=hashes.SHA256()
        , label=None
      )
    )
    return b64url_encode(ciphertext)

  def decrypt(self, ciphertext_b64: str) -> bytes:
    """Decrypts URL-safe Base64 ciphertext using RSA-OAEP-2048."""
    import base64
    # Fix padding for standard b64 decode
    missing_padding = len(ciphertext_b64) % 4
    if missing_padding:
      ciphertext_b64 += '=' * (4 - missing_padding)
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
    
    return self.private_key.decrypt(
      ciphertext
      , padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256())
        , algorithm=hashes.SHA256()
        , label=None
      )
    )

  def get_jwks(self, use: str = "sig") -> dict:
    """Returns the public key in JWK format with a specific 'use'."""
    numbers = self.public_key.public_numbers()
    
    def to_base64url(n):
      return b64url_encode(n.to_bytes((n.bit_length() + 7) // 8, 'big'))

    return {
      "kty": "RSA"
      , "alg": "RS256" if use == "sig" else "RSA-OAEP-2048"
      , "use": use
      , "n": to_base64url(numbers.n)
      , "e": to_base64url(numbers.e)
    }

  def get_jwks_set(self, enc_manager: "CryptoManager") -> dict:
    """Returns a JWKS containing both this signing key and a provided encryption key."""
    return {
      "keys": [
        self.get_jwks(use="sig")
        , enc_manager.get_jwks(use="enc")
      ]
    }
