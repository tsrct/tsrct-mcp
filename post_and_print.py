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
  IDENTITY_FILE = os.path.expanduser("~/.tsrct/identity.json")
  if not os.path.exists(IDENTITY_FILE):
    print("Error: identity.json not found.")
    return

  with open(IDENTITY_FILE, "r") as f:
    data = json.load(f)
    AGENT_UID = data["uid"]
    AGENT_SRC = data["src"]
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
    , "key": AGENT_UID # key ID is identical to agent uid
    , "agt": True
    , "uid": doc_uid
    , "len": len(body_b64)
    , "sha": calculate_tsrct_sha256(body_b64)
    , "sig": body_sig
    , "acl": "acl_pub"
  }

  tdoc = TDoc(header=TDocHeader(**header_data), body_b64=body_b64)
  header_b64 = b64url_encode(tdoc.header.model_dump_json(by_alias=True, exclude_none=True).encode('utf-8'))
  
  # Outer JWS signature
  sign_input = f"{header_b64}.{tdoc.body_b64}".encode('utf-8')
  tdoc.signature_b64 = AGENT_SIG_CRYPTO.sign(sign_input)

  raw_tdoc = tdoc.encode()

  API_BASE_URL = "http://localhost:8080"
  async with httpx.AsyncClient(timeout=10.0) as client:
    try:
      print(f"[*] Posting T-Doc to API root...")
      response = await client.post(
        f"{API_BASE_URL}/"
        , content=raw_tdoc
        , headers={"Content-Type": "text/plain"}
      )
      print(f"[<] Response Status Code: {response.status_code}")
      print(f"[<] Response Raw Body:\n{response.text}")
    except Exception as e:
      print(f"[!] Request failed: {e}")

if __name__ == "__main__":
  asyncio.run(main())
