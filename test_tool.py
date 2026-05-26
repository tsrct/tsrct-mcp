import asyncio
import httpx
import uuid
import json
import os
import sys

# Add the current directory to sys.path to import crypto
sys.path.append(os.getcwd())

from crypto import CryptoManager

async def test():
    API_BASE_URL = "http://localhost:8080"
    IDENTITY_FILE = "identity.json"
    
    print(f"[*] Reading identity...")
    if not os.path.exists(IDENTITY_FILE):
        print("[!] Error: identity.json not found.")
        return

    with open(IDENTITY_FILE, "r") as f:
        data = json.load(f)
        uid = data["uid"]
        sig_crypto = CryptoManager(data["sig_private_key"].encode('utf-8'))
        enc_crypto = CryptoManager(data["enc_private_key"].encode('utf-8'))

    session_id = str(uuid.uuid4())
    jwks = sig_crypto.get_jwks_set(enc_crypto)
    slf = sig_crypto.get_slf(enc_crypto)

    print(f"[*] Initiating session {session_id} for UID {uid}...")
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            init_payload = {
                "sessionId": session_id
                , "publicKeyJwk": jwks
                , "slf": slf
                , "dsc": f"tsrct://ent/init/{session_id}"
                , "uid": uid
            }
            response = await client.post(
                f"{API_BASE_URL}/auth/session/init"
                , json=init_payload
            )
            print(f"[<] Response Status: {response.status_code}")
            print(f"[<] Response Body: {response.text}")
        except Exception as e:
            print(f"[!] Request failed: {e}")

if __name__ == "__main__":
    asyncio.run(test())
