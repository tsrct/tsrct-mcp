import os
import time
import uuid
import base64
import json
import io
import asyncio
import httpx
import qrcode
import sys
import random
import re
from fastmcp import FastMCP
from crypto import CryptoManager
from tdoc import TDoc, TDocHeader
from utils import validate_verhoeff, b64url_encode

# Initialize FastMCP server
mcp = FastMCP("tsrct-mcp")

# Configuration
DEV_MODE = os.getenv("TSRCT_DEV", "false").lower() == "true"
API_BASE_URL = os.getenv("TSRCT_API_URL", "http://localhost:8080" if DEV_MODE else "https://api.tsrct.io")

IDENTITY_FILE = "identity.json"

def log(msg: str):
  """Logs to stderr to avoid breaking MCP JSON-RPC protocol."""
  sys.stderr.write(f"{msg}\n")
  sys.stderr.flush()

async def initialize_identity():
  """Loads or creates a persistent agent identity with dual keys (sig and enc). UID is deferred until authorization."""
  global AGENT_SIG_CRYPTO, AGENT_ENC_CRYPTO, AGENT_UID
  
  if os.path.exists(IDENTITY_FILE):
    with open(IDENTITY_FILE, "r") as f:
      data = json.load(f)
      AGENT_UID = data.get("uid") # Might be None if not yet authorized
      AGENT_SIG_CRYPTO = CryptoManager(data["sig_private_key"].encode('utf-8'))
      AGENT_ENC_CRYPTO = CryptoManager(data["enc_private_key"].encode('utf-8'))
      return

  # If not exists, create a new cryptographic identity (UID is deferred)
  AGENT_SIG_CRYPTO = CryptoManager() # Generates new signing key
  AGENT_ENC_CRYPTO = CryptoManager() # Generates new encryption key
  AGENT_UID = None
  
  log("[!] Successfully initialized cryptographic keys. UID pending authorization.")

  # Save partial identity to file
  with open(IDENTITY_FILE, "w") as f:
    json.dump({
      "uid": AGENT_UID
      , "sig_private_key": AGENT_SIG_CRYPTO.get_private_key_pem().decode('utf-8')
      , "enc_private_key": AGENT_ENC_CRYPTO.get_private_key_pem().decode('utf-8')
    }, f, indent=2)

# These will be set by initialize_identity()
AGENT_SIG_CRYPTO = None
AGENT_ENC_CRYPTO = None
AGENT_UID = None

async def ensure_identity():
  """Guarantees cryptographic keys are initialized."""
  if AGENT_SIG_CRYPTO is None:
    await initialize_identity()

async def ensure_authorized():
  """Guarantees the agent has been assigned a UID via registration."""
  await ensure_identity()
  if AGENT_UID is None:
    raise Exception("Agent is not yet authorized. Please run propose_agent_registration first.")

@mcp.resource("tsrct://identity")
async def get_identity_status() -> str:
  """Returns the current agent identity status and UID."""
  await ensure_identity()
  return f"Agent UID: {AGENT_UID}\nStatus: {'Initialized and Persistent' if os.path.exists(IDENTITY_FILE) else 'Initialized (In-Memory Only)'}"

@mcp.resource("tsrct://docs/manual")
def get_protocol_manual() -> str:
  """Returns the core system documentation for LLM ingestion context."""
  return """
  # tsrct Protocol Manual (v1.0)
  
  ## 1. T-Doc Structure
  A T-Doc is a single line string: header.body.signature
  - header: URL-safe Base64 JSON
  - body: URL-safe Base64 payload
  - signature: RS256 signature of base64(header) + "." + base64(body)
  
  ## 2. SHA-256 Quirk
  The header 'sha' field is SHA-256(UTF8-Bytes(Base64String(bodyBytes))).
  
  ## 3. UID Validation
  All UIDs must be 25 digits and pass the Verhoeff checksum.
  They must not start with 0 or 1.
  
  ## 4. Key Exchange
  Agents use RSA-2048 for signatures (RS256) and encryption (RSA-OAEP-2048).
  Each agent registration provides a JWKS with two keys: one for 'sig' and one for 'enc'.
  """

@mcp.tool()
async def propose_agent_registration(agent_name: str, agent_description: str) -> str:
  """
  Initiates agent onboarding by creating a session on the API.
  Returns a QR code for the user to scan with their mobile app.

  agent_name: Lowercase alphanumeric string with dashes/underscores, max 32 chars.
  agent_description: Human readable description of the agent.
  """
  log(f"[*] Tool called: propose_agent_registration(agent_name='{agent_name}', agent_description='{agent_description}')")

  # Apply defaults if blank
  if not agent_name or not agent_name.strip():
    agent_name = "tsrct-local-mcp-agent"
  if not agent_description or not agent_description.strip():
    agent_description = "Automated tsrct-mcp agent"

  # Validate agent name
  if not re.match(r'^[a-z0-9_-]+$', agent_name) or len(agent_name) > 32:
    return (
      "Error: Invalid agent name. "
      "Name must be all lower case, contain only letters, numbers, dash or underscore, "
      "and be at most 32 characters long."
    )

  log("[*] Ensuring identity...")
  await ensure_identity()

  session_id = str(uuid.uuid4())
  log(f"[*] Generating cryptographic payload for session {session_id}...")
  jwks = AGENT_SIG_CRYPTO.get_jwks_set(AGENT_ENC_CRYPTO)
  
  # Convert JWKS to Base64 string for the payload
  # Ensure NO whitespace and consistent key ordering
  jwks_json = json.dumps(jwks, separators=(',', ':'), sort_keys=True)
  jwks_b64 = b64url_encode(jwks_json.encode('utf-8'))
  
  log(f"[*] JWK Base64 Length: {len(jwks_b64)}")

  # slf is the signature over the jwks_b64 string
  # slf = AGENT_SIG_CRYPTO.get_slf(AGENT_ENC_CRYPTO)
  # FIX: Explicitly sign the exact base64 string being sent to the server.
  # This guarantees Dart verifies the exact same bytes that Python signed.
  slf = AGENT_SIG_CRYPTO.sign(jwks_b64.encode('utf-8'))
  
  log(f"[*] Initiating session on API at {API_BASE_URL}...")
  async with httpx.AsyncClient(timeout=10.0) as client:
    try:
      init_payload = {
        "sessionId": session_id
        , "jwk": jwks_b64
        , "slf": slf
        , "typ": "agt"
        , "vid": agent_name
        , "dsc": agent_description
      }

      log(f"[*] Sending init_payload: {json.dumps(init_payload, indent=2)}")

      # Do not send UID, the backend will assign it upon authorization
      init_response = await client.post(
        f"{API_BASE_URL}/auth/session/init"
        , json=init_payload
      )
      init_response.raise_for_status()
      log("[*] Session initialized successfully.")
    except Exception as e:
      log(f"[!] Error initializing registration session: {str(e)}")
      return f"Error initializing registration session: {str(e)}"

    # Generate QR Code (Session URI)
    log("[*] Generating QR code image...")
    session_uri = f"tsrct://ses/{session_id}"
    qr = qrcode.QRCode(version=1, box_size=10, border=5)

    qr.add_data(session_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_base64 = base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')
    
    log("[*] QR code generated. Returning response.")
    markdown_image = f"![Scan to Authorize Agent](data:image/png;base64,{img_base64})"
    
    # Generate ASCII QR Code for terminal users
    f = io.StringIO()
    qr.print_ascii(out=f)
    ascii_qr = f.getvalue()

    return (
      f"Agent Registration Initiated for '{agent_name}'\n"
      f"Session ID: {session_id}\n"
      f"Agent UID: {AGENT_UID}\n\n"
      f"Please scan this QR code with your tsrct mobile app to authorize this agent:\n\n"
      f"--- START TERMINAL QR CODE ---\n"
      f"{ascii_qr}\n"
      f"--- END TERMINAL QR CODE ---\n\n"
      f"Markdown version (if supported by your UI):\n"
      f"{markdown_image}\n\n"
      f"After scanning, I will poll the server for 5 minutes to confirm authorization."
    )

@mcp.tool()
async def wait_for_registration(session_id: str) -> str:
  """
  Polls the API for up to 5 minutes to check if the session has been authorized.
  """
  start_time = time.time()
  timeout = 5 * 60 # 5 minutes
  
  async with httpx.AsyncClient() as client:
    while time.time() - start_time < timeout:
      try:
        status_response = await client.get(f"{API_BASE_URL}/auth/session/{session_id}/status")
        status_response.raise_for_status()
        status_data = status_response.json()
        
        if status_data.get("status") == "AUTHORIZED":
          global AGENT_UID
          AGENT_UID = status_data.get("agtDocUid")
          
          if AGENT_UID:
             log(f"[*] Agent authorized! Assigned UID: {AGENT_UID}")
             with open(IDENTITY_FILE, "w") as f:
               json.dump({
                 "uid": AGENT_UID
                 , "sig_private_key": AGENT_SIG_CRYPTO.get_private_key_pem().decode('utf-8')
                 , "enc_private_key": AGENT_ENC_CRYPTO.get_private_key_pem().decode('utf-8')
               }, f, indent=2)
          else:
             log("[!] Warning: Authorized but no agtDocUid received.")

          return f"SUCCESS: Session {session_id} has been authorized!\nAssigned Agent UID: {AGENT_UID}\nUser UID: {status_data.get('userUid')}\nKey UID: {status_data.get('keyUid')}"
        
        await asyncio.sleep(5) # Poll every 5 seconds
      except Exception as e:
        # Intermittent errors are ignored
        await asyncio.sleep(5)

    return f"TIMEOUT: Registration session {session_id} timed out after 5 minutes."

@mcp.tool()
async def send_a2a_message(recipient_uid: str, message: str) -> str:
  """
  Sends an encrypted and signed T-Doc message to another agent.
  """
  await ensure_authorized()
  if not validate_verhoeff(recipient_uid):
    return f"Error: Invalid recipient UID '{recipient_uid}' (Verhoeff check failed)."

  async with httpx.AsyncClient() as client:
    # 1. Discover Recipient's Public Key
    try:
      response = await client.get(f"{API_BASE_URL}/registry/{recipient_uid}")
      response.raise_for_status()
      registry_data = response.json()
      # Find encryption key
      enc_key_pem = None
      for key in registry_data.get("keys", []):
        if key.get("use") == "enc":
          enc_key_pem = key.get("pem")
          break
      
      if not enc_key_pem:
        return f"Error: No encryption key found for recipient {recipient_uid}."
        
    except Exception as e:
      return f"Error fetching registry for {recipient_uid}: {str(e)}"

    # 2. Encrypt Message
    ciphertext_b64 = AGENT_ENC_CRYPTO.encrypt(enc_key_pem.encode('utf-8'), message.encode('utf-8'))

    # 3. Build and Sign T-Doc
    doc_uid = str(uuid.uuid4()) # Temporary UID generation
    header_data = {
      "cls": "doc"
      , "typ": "msg"
      , "its": int(time.time())
      , "uid": doc_uid
      , "src": AGENT_UID
      , "acl": "acl_pri"
    }
    
    tdoc = TDoc.build(header_data, ciphertext_b64.encode('utf-8'))
    
    # Sign: base64(header) + "." + base64(body)
    header_b64 = b64url_encode(tdoc.header.model_dump_json(by_alias=True, exclude_none=True).encode('utf-8'))
    sign_input = f"{header_b64}.{tdoc.body_b64}".encode('utf-8')
    tdoc.signature_b64 = AGENT_SIG_CRYPTO.sign(sign_input)

    # 4. Transmit
    try:
      post_response = await client.post(
        f"{API_BASE_URL}/"
        , content=tdoc.encode()
        , headers={"Content-Type": "text/plain"}
      )
      post_response.raise_for_status()
      return f"Message sent successfully to {recipient_uid}. T-Doc Hash: {tdoc.header.sha}"
    except Exception as e:
      return f"Error transmitting T-Doc: {str(e)}"

if __name__ == "__main__":
  mcp.run()
