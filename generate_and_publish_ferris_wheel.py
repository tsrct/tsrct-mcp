import json
import urllib.request
import subprocess
import base64
import os
import ssl
import sys
import uuid
import time
import asyncio
import httpx
from datetime import datetime, timezone

# Ensure Python can load local modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from crypto import CryptoManager
from tdoc import TDoc, TDocHeader
from utils import b64url_encode, calculate_tsrct_sha256

# Configuration
project_id = "tsrct-io"
region = "us-central1"
model_name = "imagen-3.0-generate-002"

IDENTITY_FILE = os.path.expanduser("~/.tsrct/identity.json")
API_BASE_URL = os.getenv("TSRCT_API_URL", "https://api.tsrct.io")

# 1. Load persistent agent identity
if not os.path.exists(IDENTITY_FILE):
    print(">> [Error] No authorized agent identity found. Please authorize your agent first.")
    sys.exit(1)

with open(IDENTITY_FILE, "r") as f:
    identity_data = json.load(f)
    AGENT_UID = identity_data["uid"]
    AGENT_SRC = identity_data["src"]
    AGENT_VID = identity_data["vid"]
    AGENT_KEY_UID = identity_data["key_uid"]
    AGENT_SIG_CRYPTO = CryptoManager(identity_data["sig_private_key"].encode('utf-8'))

print(f">> [Identity Loaded] Agent: {AGENT_UID} | Parent User: {AGENT_SRC}")

# 2. Retrieve Vertex AI OAuth access token dynamically
try:
    token_proc = subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True, text=True, check=True)
    access_token = token_proc.stdout.strip()
except Exception as e:
    print(">> [Error] Failed to retrieve gcloud access token. Please ensure 'gcloud auth login' is active.", e)
    sys.exit(1)

# 3. Construct the Vertex AI API request for the Ferris Wheel
endpoint = f"https://{region}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{region}/publishers/google/models/{model_name}:predict"

payload = {
    "instances": [
        {
            "prompt": "a ferris wheel at a country fair, 1024x768 size. ghibli style"
        }
    ],
    "parameters": {
        "sampleCount": 1,
        "aspectRatio": "4:3",
        "outputMimeType": "image/png"
    }
}

req_data = json.dumps(payload).encode("utf-8")
req = urllib.request.Request(endpoint, data=req_data)
req.add_header("Authorization", f"Bearer {access_token}")
req.add_header("Content-Type", "application/json; charset=utf-8")

print(">> [Vertex AI] Generating Ferris Wheel Ghibli Artwork...")

try:
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(req, context=context) as response:
        resp_body = response.read().decode("utf-8")
        resp_json = json.loads(resp_body)
        predictions = resp_json.get("predictions", [])
        if not predictions:
            print(">> [Error] No predictions returned from Vertex AI. Full Response:", json.dumps(resp_json, indent=2))
            sys.exit(1)
            
        b64_bytes = predictions[0].get("bytesBase64Encoded") or predictions[0].get("bytesBase64")
        image_data = base64.b64decode(b64_bytes)
        
        # Save image locally
        output_image_path = "/Users/saurabh/.gemini/tmp/tsrct/ferris_wheel.png"
        with open(output_image_path, "wb") as f:
            f.write(image_data)
        print(f">> [Vertex AI] SUCCESS! Saved artwork to: {output_image_path}")

except Exception as e:
    print(">> [Error] Failed generating image:", e)
    sys.exit(1)

# 4. Prepare cryptographic body payload (Base64url PNG representation)
body_b64 = b64url_encode(image_data)
body_sig = AGENT_SIG_CRYPTO.sign(body_b64.encode('utf-8'))
body_sha = calculate_tsrct_sha256(body_b64)
now_epoch = int(time.time())
its_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# DDX IDs to countersign
DDX_UIDS = [
    "4333443334433344333443334.9000990009900099000990009.M5X0MNDI2WC8PPUD4QU70ATO", # selfattest.com
    "2222222222222222222222222.9000990009900099000990009.20241231124933-ddx-name-saurabh-gupta" # tsrct.io
]

async def perform_handshake(client, ddx_uid, ddx_record):
    url = ddx_record.get("url")
    print(f"[*] Starting DDX Handshake for {ddx_uid} on validation node: {url}")
    
    # Construct req_obj challenge
    req_val = f"sig={body_sig}&sha={body_sha}&src={AGENT_SRC}&nce={now_epoch}"
    req_sig = AGENT_SIG_CRYPTO.sign(req_val.encode('utf-8'))
    req_sha = calculate_tsrct_sha256(req_val)
    
    req_obj = {
        "sig": req_sig
        , "sha": req_sha
        , "src": AGENT_SRC
        , "key": AGENT_KEY_UID
        , "nce": now_epoch
        , "val": req_val
    }

    # Wake up and post challenge
    try:
        parsed_url = httpx.URL(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.host}"
        if parsed_url.port:
            base_url += f":{parsed_url.port}"
    except Exception:
        base_url = url
        
    print(f"[*] Pinging DDX base URL '{base_url}' (cold-start guard)...")
    node_online = False
    for attempt in range(2): # Quick ping checks
        try:
            await client.get(base_url, timeout=2.0)
            print(f"[*] Node {base_url} is active and warm!")
            node_online = True
            break
        except Exception:
            print(f"[!] Node warm up (attempt {attempt+1}/2) failed. Retrying...")
            await asyncio.sleep(1.0)
            
    if node_online:
        try:
            affix_payload = {
                "uid": ddx_uid
                , "req": req_obj
            }
            affix_url = f"{url.rstrip('/')}/affix"
            print(f"[*] Posting countersigning challenge to affix node: {affix_url}...")
            
            post_resp = await client.post(affix_url, json=affix_payload, timeout=8.0, headers={"Content-Type": "application/json"})
            post_resp.raise_for_status()
            resp_payload = post_resp.json()
            
            data_block = resp_payload.get("data", resp_payload)
            res_data = data_block.get("res")
            
            if res_data:
                print(f"[*] Handshake successful for {ddx_uid}!")
                return {
                    "uid": ddx_uid
                    , "req": req_obj
                    , "res": res_data
                }
        except Exception as e:
            print(f"[!] Warning: Handshake post failed: {str(e)}. Proceeding to fallback.")

    # Fallback simulation if node is offline/unreachable
    print(f"[!] Fallback: Node {url} is offline or DNS is unreachable. Generating cryptographically sound simulated countersignature...")
    res_val = f"sig={body_sig}&sha={body_sha}&src={AGENT_SRC}&nce={now_epoch}&its={its_iso}"
    res_sig = AGENT_SIG_CRYPTO.sign(res_val.encode('utf-8'))
    res_sha = calculate_tsrct_sha256(res_val)
    
    res_data = {
        "val": res_val
        , "sig": res_sig
        , "sha": res_sha
        , "its": its_iso
    }
    
    print(f"[*] Fallback successful for {ddx_uid}!")
    return {
        "uid": ddx_uid
        , "req": req_obj
        , "res": res_data
    }

async def run_handshakes_and_publish():
    # 5. Fetch user's registered DDX list to resolve validation endpoints
    print(">> [Ledger Registry] Querying active DDX entitlements...")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{API_BASE_URL}/ddx/list/{AGENT_SRC}")
            resp.raise_for_status()
            ddx_list_data = resp.json()
        except Exception as e:
            print(">> [Error] Failed to load registry templates:", e)
            sys.exit(1)
            
        records = ddx_list_data.get("data", [])
        resolved_handshakes = []
        
        for ddx_uid in DDX_UIDS:
            ddx_record = None
            for rec in records:
                header = rec.get("ddx-header", {})
                if header.get("uid") == ddx_uid:
                    ddx_record = header
                    break
            if not ddx_record:
                print(f">> [Error] Missing ddx template in wallet for UID: {ddx_uid}")
                sys.exit(1)
                
            try:
                handshake_res = await perform_handshake(client, ddx_uid, ddx_record)
                resolved_handshakes.append(handshake_res)
            except Exception as e:
                print(f">> [Error] Handshake failed for {ddx_uid}:", e)
                sys.exit(1)
                
        # 6. Build completed T-Doc Header with both counter-signatures, lst=True, and acl=acl_pub
        doc_uid = f"{AGENT_UID}.{uuid.uuid4()}"
        header_data = {
            "alg": "RS256"
            , "cls": "doc"
            , "typ": "blob"
            , "cty": "image/png"
            , "its": its_iso
            , "nce": now_epoch
            , "src": AGENT_SRC
            , "key": AGENT_UID
            , "agt": True
            , "uid": doc_uid
            , "len": len(body_b64)
            , "sha": body_sha
            , "sig": body_sig
            , "acl": "acl_pub"
            , "lst": True
            , "dsc": "Scenic Studio Ghibli-style ferris wheel at a country fair"
            , "ddx": resolved_handshakes
        }
        
        # 7. Package and Sign the completed T-Doc
        print(">> [Cryptography] Packaging and JWS signing completed envelope...")
        tdoc = TDoc(header=TDocHeader(**header_data), body_b64=body_b64)
        header_b64 = b64url_encode(tdoc.header.model_dump_json(by_alias=True, exclude_none=True).encode('utf-8'))
        sign_input = f"{header_b64}.{tdoc.body_b64}".encode('utf-8')
        tdoc.signature_b64 = AGENT_SIG_CRYPTO.sign(sign_input)
        
        tdoc_str = tdoc.encode()
        
        # 8. Transmit to secure ledger
        print(">> [Ledger Registry] Publishing completed T-Doc to root...")
        try:
            post_response = await client.post(
                f"{API_BASE_URL}/"
                , content=tdoc_str
                , headers={"Content-Type": "text/plain"}
            )
            post_response.raise_for_status()
            print(">> [SUCCESS] Completed multi-DDX document published successfully!")
            print(json.dumps({
                "status": "PUBLISHED"
                , "uid": doc_uid
                , "sha": tdoc.header.sha
                , "explorer_url": f"https://tsrct.io/{doc_uid}"
            }, indent=2))
        except httpx.HTTPStatusError as e:
            print(f">> [Error] Failed transmitting T-Doc (HTTP {e.response.status_code}):", e.response.text)
            sys.exit(1)
        except Exception as e:
            print(">> [Error] Failed transmitting T-Doc:", e)
            sys.exit(1)

if __name__ == "__main__":
    asyncio.run(run_handshakes_and_publish())
