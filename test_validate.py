import asyncio
import json
import os
import sys
import uuid
import time
import httpx
from datetime import datetime, timezone

# Add the current directory to sys.path to import crypto
sys.path.append(os.getcwd())

from crypto import CryptoManager
from tdoc import TDoc, TDocHeader
from utils import b64url_encode, calculate_tsrct_sha256

async def main():
  IDENTITY_FILE = "identity.json"
  if not os.path.exists(IDENTITY_FILE):
    print("Error: identity.json not found.")
    return

  with open(IDENTITY_FILE, "r") as f:
    data = json.load(f)
    AGENT_UID = data["uid"]
    AGENT_KEY_UID = data["key_uid"]
    AGENT_SIG_CRYPTO = CryptoManager(data["sig_private_key"].encode('utf-8'))
    AGENT_ENC_CRYPTO = CryptoManager(data["enc_private_key"].encode('utf-8'))

  text = "hello world from tsrct mcp"
  doc_uid = f"{AGENT_UID}.{uuid.uuid4()}"
  body_b64 = b64url_encode(text.encode('utf-8'))
  now_epoch = int(time.time())
  its_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

  # Generate body signature over the Base64 body string
  body_sig = AGENT_SIG_CRYPTO.sign(body_b64.encode('utf-8'))

  header_data = {
    "alg": "RS256"
    , "cls": "doc"
    , "typ": "text"
    , "cty": "text/plain"
    , "its": its_iso
    , "nce": now_epoch
    , "src": AGENT_UID
    , "key": AGENT_UID # Try both AGENT_UID and AGENT_KEY_UID if needed
    , "uid": doc_uid
    , "len": len(body_b64)
    , "sha": calculate_tsrct_sha256(body_b64)
    , "sig": body_sig
    , "acl": "acl_pub"
  }

  tdoc = TDoc(header=TDocHeader(**header_data), body_b64=body_b64)
  header_b64 = b64url_encode(tdoc.header.model_dump_json(by_alias=True, exclude_none=True).encode('utf-8'))
  sign_input = f"{header_b64}.{tdoc.body_b64}".encode('utf-8')
  tdoc.signature_b64 = AGENT_SIG_CRYPTO.sign(sign_input)

  print(f"\n[*] Generated T-Doc Header:\n{tdoc.header.model_dump_json(by_alias=True, exclude_none=True, indent=2)}")

  # Test local validation using public keys fetched from API
  async with httpx.AsyncClient() as client:
    try:
      print(f"\n[*] Fetching registered public keys for {AGENT_UID} from local API...")
      resp = await client.get(f"http://localhost:8080/{AGENT_UID}/body")
      resp.raise_for_status()
      jwk_set = resp.json()
      
      jwk = jwk_set["keys"][0] # First key is 'sig'
      print(f"[!] Retrieved JWK modulus starts with: {jwk['n'][:30]}...")

      # Verify body signature (sig field) over body_b64
      sig_ok = CryptoManager.verify_signature(jwk, body_b64.encode('utf-8'), body_sig)
      print(f"[!] Header 'sig' local check: {'PASSED' if sig_ok else 'FAILED'}")

      # Verify outer envelope JWS signature over header_b64.body_b64
      jws_ok = CryptoManager.verify_signature(jwk, sign_input, tdoc.signature_b64)
      print(f"[!] Outer Envelope JWS local check: {'PASSED' if jws_ok else 'FAILED'}")

    except Exception as e:
      print(f"[!] Verification test failed: {e}")

if __name__ == "__main__":
  asyncio.run(main())
