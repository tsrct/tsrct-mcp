import asyncio
import os
import json
import httpx
import random
import sys
from crypto import CryptoManager

# Configuration
API_BASE_URL = "http://localhost:8080"
IDENTITY_FILE = "identity.json"

def log(msg: str):
  sys.stderr.write(f"{msg}\n")
  sys.stderr.flush()

async def initialize_identity():
  if os.path.exists(IDENTITY_FILE):
    log("[*] Identity already exists.")
    return

  max_retries = 5
  retry_count = 0
  async with httpx.AsyncClient() as client:
    while retry_count < max_retries:
      retry_count += 1
      base_number = str(random.randint(2, 9)) + "".join([str(random.randint(0, 9)) for _ in range(23)])
      
      try:
        log(f"[*] Fetching checksum for {base_number}...")
        checksum_response = await client.get(f"{API_BASE_URL}/i/checksum/{base_number}")
        checksum_response.raise_for_status()
        resp_json = checksum_response.json()
        data = resp_json.get("data", {})
        if "output" not in data:
          log(f"[!] Error: 'output' key missing: {resp_json}")
          continue
        uid = data["output"]
        
        log(f"[*] Checking if UID {uid} exists...")
        exists_response = await client.get(f"{API_BASE_URL}/i/exists/{uid}")
        exists_response.raise_for_status()
        exists_data = exists_response.json().get("data", {})
        
        if not exists_data.get("uidExists", True):
          AGENT_SIG_CRYPTO = CryptoManager()
          AGENT_ENC_CRYPTO = CryptoManager()
          
          with open(IDENTITY_FILE, "w") as f:
            json.dump({
              "uid": uid
              , "sig_private_key": AGENT_SIG_CRYPTO.get_private_key_pem().decode('utf-8')
              , "enc_private_key": AGENT_ENC_CRYPTO.get_private_key_pem().decode('utf-8')
            }, f, indent=2)
          log(f"[!] Success! Created identity: {uid}")
          return
      except Exception as e:
        log(f"[!] Error: {e}")
        await asyncio.sleep(1)

if __name__ == "__main__":
  asyncio.run(initialize_identity())
