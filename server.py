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
from datetime import datetime, timezone
from typing import Optional
from fastmcp import FastMCP
from crypto import CryptoManager
from tdoc import TDoc, TDocHeader
from utils import validate_verhoeff, b64url_encode, calculate_tsrct_sha256

# Initialize FastMCP server
mcp = FastMCP("tsrct-mcp")

# Configuration
DEV_MODE = os.getenv("TSRCT_DEV", "false").lower() == "true"
API_BASE_URL = os.getenv("TSRCT_API_URL", "http://localhost:8080" if DEV_MODE else "https://api.tsrct.io")

IDENTITY_DIR = os.path.expanduser("~/.tsrct")
IDENTITY_FILE = os.path.join(IDENTITY_DIR, "identity.json")

def log(msg: str):
  """Logs to stderr to avoid breaking MCP JSON-RPC protocol."""
  sys.stderr.write(f"{msg}\n")
  sys.stderr.flush()

async def initialize_identity():
  """Loads or creates a persistent agent identity with dual keys (sig and enc). UID is deferred until authorization."""
  global AGENT_SIG_CRYPTO, AGENT_ENC_CRYPTO, AGENT_UID, AGENT_SRC, AGENT_VID, AGENT_KEY_UID
  
  # Ensure the secure home directory exists
  os.makedirs(IDENTITY_DIR, exist_ok=True)
  
  if os.path.exists(IDENTITY_FILE):
    with open(IDENTITY_FILE, "r") as f:
      data = json.load(f)
      AGENT_UID = data.get("uid") # Might be None if not yet authorized
      AGENT_SRC = data.get("src")
      AGENT_VID = data.get("vid")
      AGENT_KEY_UID = data.get("key_uid")
      AGENT_SIG_CRYPTO = CryptoManager(data["sig_private_key"].encode('utf-8'))
      AGENT_ENC_CRYPTO = CryptoManager(data["enc_private_key"].encode('utf-8'))
      return

  # If not exists, create a new cryptographic identity (UID is deferred)
  AGENT_SIG_CRYPTO = CryptoManager() # Generates new signing key
  AGENT_ENC_CRYPTO = CryptoManager() # Generates new encryption key
  AGENT_UID = None
  AGENT_SRC = None
  AGENT_VID = None
  AGENT_KEY_UID = None
  
  log("[!] Successfully initialized cryptographic keys. UID pending authorization.")

  # Save partial identity to file
  with open(IDENTITY_FILE, "w") as f:
    json.dump({
      "uid": AGENT_UID
      , "src": AGENT_SRC
      , "vid": AGENT_VID
      , "key_uid": AGENT_KEY_UID
      , "sig_private_key": AGENT_SIG_CRYPTO.get_private_key_pem().decode('utf-8')
      , "enc_private_key": AGENT_ENC_CRYPTO.get_private_key_pem().decode('utf-8')
    }, f, indent=2)

# These will be set by initialize_identity()
AGENT_SIG_CRYPTO = None
AGENT_ENC_CRYPTO = None
AGENT_UID = None
AGENT_SRC = None
AGENT_VID = None
AGENT_KEY_UID = None

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
  """Returns the current agent identity status and details."""
  await ensure_identity()
  return (
    f"Agent UID: {AGENT_UID}\n"
    f"Registered Key ID (KID): {AGENT_KEY_UID}\n"
    f"User UID (SRC): {AGENT_SRC}\n"
    f"Virtual ID (VID): {AGENT_VID}\n"
    f"Status: {'Initialized and Persistent' if os.path.exists(IDENTITY_FILE) else 'Initialized (In-Memory Only)'}"
  )

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

  ## 5. Document Class ('cls:doc') Schema & Constraints
  When creating a new T-Doc of class `cls:doc` (e.g., standard text or JSON payloads), the header MUST comply with these field constraints retrieved from the schema registry:

  ### A. Mandatory Fields:
  *   `uid` (string, required): A unique document identifier, formatted as `{src_uid}.{uuid_or_timestamp}`.
  *   `cls` (string, required): The document class. Must be `"doc"`.
  *   `typ` (string, required): The document body payload type. Must be one of: `"text"`, `"json"`, `"blob"`, `"data"`, `"pbuf"`, `"post"`.
  *   `cty` (string, required): The MIME content type of the decoded body (e.g., `"text/plain"`, `"application/json"`).
  *   `its` (string, required): Issue timestamp in ISO date format: `yyyy-MM-dd'T'HH:mm:ss'Z'` (e.g. `"2026-05-26T12:14:53Z"`).
  *   `nce` (integer, required): Nonce in seconds since epoch as a long (integer). Aligned with system seconds within a +/- 10-second window.
  *   `src` (string, required): The creator/author's UID (e.g., the Agent's UID).
  *   `key` (string, required): The public key ID used for signing, formatted as `uid.kid` (e.g. `AGENT_UID.sig_key_id`).
  *   `alg` (string, required): The signature algorithm. Must be `"RS256"`.
  *   `len` (integer, required): The character length of the unpadded Base64 body string.
  *   `sha` (string, required): SHA-256 hash calculated over the bytes of the **Base64 body string** (not decoded bytes).
  *   `sig` (string, required): Signature calculated over the **Base64 body string** (the JWA JWS RS256 standard).

  ### B. Important Optional Fields:
  *   `acl` (string, optional): Access control level. Must be `"acl_pub"` (public) or `"acl_pri"` (private). If absent, defaults to private.
  *   `dsc` (string, optional): Description of the document. Max 1024 characters.
  *   `cid` (string, optional): Correlation ID, used to forward-chain related T-Docs. If present, `seq` is mandatory.
  *   `seq` (integer, optional): Monotonically increasing sequence number (such as epoch milliseconds) linked to a `cid`.
  *   `ref` (array of objects, optional): Reference to other T-Docs. Each object contains `uid`, `sig`, `sha`, and `tds`.
  """

@mcp.resource("tsrct://docs/mcp-guide")
def get_mcp_guide() -> str:
  """Returns a detailed operational and concepts guide for LLMs loading this MCP."""
  return """
  # tsrct MCP AI Integration & Operations Guide

  This guide provides the necessary technical and architectural context for any LLM executing tools or resources on this MCP server.

  ---

  ## 1. High-Level Trust Model
  - **The Root of Trust** in the `tsrct` ecosystem resides on the user's mobile application.
  - **Local Software Agents** (such as this MCP server) generate their own cryptographic keys locally, but their authority is *deferred* until they are cryptographically "blessed" (authorized) by a user.
  - Once authorized, the agent receives an official identity and can cryptographically sign T-Docs (`cls:doc`, `typ:msg`) that are globally accepted by the ledger and other nodes.

  ---

  ## 2. Deferred UID Onboarding & The Blessing Handshake
  When a new agent is created, it goes through a specific session-based onboarding flow:

  ### Step A: Local Key Initialization
  - The agent generates two RSA-2048 keypairs locally: one for signing (`sig`, RS256) and one for encryption (`enc`, RSA-OAEP-2048).
  - These keys are stored locally in `identity.json`. **At this stage, the agent's UID is None.**

  ### Step B: Session Proposal (`propose_agent_registration`)
  - To request an identity, the agent initiates an API handshake via `POST /auth/session/init`.
  - **Payload Constraints**:
    *   `vid`: The requested agent name (Virtual ID). Must be lowercase, alphanumeric/dash/underscore, max 32 chars.
    *   `dsc`: The agent description.
    *   `jwk`: The **Base64-encoded string** of the compact public JWKS JSON (not a JSON object).
    *   `slf`: The Inception Signature. This is the RS256 signature generated over the **UTF-8 bytes of the JWK Base64 string** (not the raw JSON bytes, nor the decoded bytes).
  - The tool outputs an ASCII QR code representing the session URI: `tsrct://ses/{sessionId}`.

  ### Step C: The Handshake Poll (`wait_for_registration`)
  - While the user scans the terminal QR code using their authenticated mobile app, the agent polls the status via `/auth/session/{sessionId}/status`.
  - The API wraps payloads in a top-level `data` block.
  - When the user signs the key registration T-Doc (using descriptor `tsrct://ent/init/{sessionId}`), the session transitions to `status = AUTHORIZED`.
  - **Identifier Resolution**: Once authorized, the polling agent extracts and persists:
    *   `uid`: The assigned agent UID (e.g., `<user_uid>.agt.<timestamp>-<hash>`).
    *   `src`: The parent user's UID who blessed the agent (stored locally as `AGENT_SRC`).
    *   `vid`: The Virtual ID / lowercase bound name (stored locally as `AGENT_VID`).
    All three identifiers are merged into `identity.json` alongside the private keys, finalizing the handshake.

  ---

  ## 3. Data Querying & Dynamic Payload Parsing
  The server provides tools to query any registered identity or T-Doc in the network:
  - `get_tdoc_header(uid)`: Retrieves the metadata JSON header.
  - `get_full_tdoc(uid)`: Retrieves the raw single-line T-Doc representation (`header.body.signature`).
  - `get_tdoc_body(uid)`: Fetches the payload body. Crucially, the body is decoded based on its returned `Content-Type` header:
    *   `application/json`: Parsed and beautifully indented.
    *   `image/*`: Base64 encoded and wrapped in an inline Markdown image tag (`data:image/*;base64,...`).
    *   `text/*`: Returned as plain text.
    *   `application/octet-stream`: Encoded as raw Base64.

  ---

  ## 4. Cryptographic Validation (`validate_tdoc`)
  Any LLM can validate the authenticity of a local or downloaded T-Doc string via the `validate_tdoc` tool:
  - **Format Verification**: The T-Doc must contain exactly 3 dot-separated Base64Url sections: `header.body.signature`.
  - **Body Hash Verification (The SHA-256 Quirk)**:
    *   Do NOT hash the decoded bytes of the body.
    *   Instead, calculate the SHA-256 hash of the **UTF-8 bytes of the Base64 body string** (the second dot-separated section of the T-Doc as-is).
    *   This hash must match the header's `sha` field.
  - **Signature Verification**:
    *   Retrieve the public key ID from the header's `key` field.
    *   Query the API's public key endpoint `GET /{key}/body` to resolve the signing JWK.
    *   Verify the `RS256` signature locally using the decrypted RSA parameters (`n`, `e`) over the exact UTF-8 bytes of the string `header_b64.body_b64` (the first and second parts joined with a period).
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
        
        # API wraps payload in 'data'
        data_obj = status_data.get("data", {})
        
        if data_obj.get("status") == "AUTHORIZED":
          global AGENT_UID, AGENT_SRC, AGENT_VID, AGENT_KEY_UID
          AGENT_UID = data_obj.get("uid")
          AGENT_SRC = data_obj.get("src")
          AGENT_VID = data_obj.get("vid")
          AGENT_KEY_UID = AGENT_UID # key_uid is identical to agent uid
          
          if AGENT_UID:
             log(f"[*] Agent authorized! Assigned UID: {AGENT_UID}")
             with open(IDENTITY_FILE, "w") as f:
               json.dump({
                 "uid": AGENT_UID
                 , "src": AGENT_SRC
                 , "vid": AGENT_VID
                 , "key_uid": AGENT_KEY_UID
                 , "sig_private_key": AGENT_SIG_CRYPTO.get_private_key_pem().decode('utf-8')
                 , "enc_private_key": AGENT_ENC_CRYPTO.get_private_key_pem().decode('utf-8')
               }, f, indent=2)
          else:
             log("[!] Warning: Authorized but no uid received in data payload.")

          return f"SUCCESS: Session {session_id} has been authorized!\nAssigned Agent UID: {AGENT_UID}\nAssigned Key UID (KID): {AGENT_KEY_UID}\nUser UID: {data_obj.get('userUid')}\nKey UID: {data_obj.get('keyUid')}"
        
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

    # Calculate body signature (sig) generated over the Base64 ciphertext string
    body_sig = AGENT_SIG_CRYPTO.sign(ciphertext_b64.encode('utf-8'))
    body_sha = calculate_tsrct_sha256(ciphertext_b64)

    # 3. Build and Sign T-Doc
    doc_uid = f"{AGENT_UID}.{uuid.uuid4()}"
    its_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    now_epoch = int(time.time())
    header_data = {
      "cls": "doc"
      , "typ": "msg"
      , "cty": "application/octet-stream"
      , "its": its_iso
      , "nce": now_epoch
      , "uid": doc_uid
      , "src": AGENT_UID
      , "key": AGENT_KEY_UID # The registered public key ID (uid.kid format)
      , "len": len(ciphertext_b64)
      , "sha": body_sha
      , "sig": body_sig # Put the body signature inside the header
      , "acl": "acl_pri"
      , "alg": "RS256"
    }
    
    tdoc = TDoc(header=TDocHeader(**header_data), body_b64=ciphertext_b64)
    
    # JWS Signature: base64(header) + "." + base64(body)
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

@mcp.tool()
async def create_and_publish_tdoc(text: str, description: Optional[str] = "Signed doc from MCP", content_type: Optional[str] = "text/plain") -> str:
  """
  Creates and publishes a new signed 'cls:doc' T-Doc with standard body text or binary base64 payloads.
  """
  await ensure_authorized()
  log(f"[*] Tool called: create_and_publish_tdoc(len={len(text)}, cty={content_type})")

  # 1. Generate T-Doc UID formatted as {src_uid}.{uuid}
  doc_uid = f"{AGENT_UID}.{uuid.uuid4()}"
  log(f"[*] Generated T-Doc UID: {doc_uid}")

  # 2. Handle Base64-encoded image/binary payloads directly without double-encoding
  if content_type and (content_type.startswith("image/") or content_type == "application/octet-stream"):
    # Clean string from any formatting artifacts
    body_b64 = text.strip().replace("\n", "").replace("\r", "").replace(" ", "").replace("\t", "")
    typ_field = "blob"
    cty_field = content_type
  else:
    body_b64 = b64url_encode(text.encode('utf-8'))
    typ_field = "text"
    cty_field = "text/plain"

  now_epoch = int(time.time())
  its_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

  # Calculate body signature (sig) generated over the Base64 body string
  body_sig = AGENT_SIG_CRYPTO.sign(body_b64.encode('utf-8'))

  # 3. Construct the mandatory Header Fields
  header_data = {
    "alg": "RS256"
    , "cls": "doc"
    , "typ": typ_field
    , "cty": cty_field
    , "its": its_iso
    , "nce": now_epoch
    , "src": AGENT_SRC # The agent signs on behalf of the originator
    , "key": AGENT_UID # The agent UID itself resolves to its public key registration document
    , "agt": True # set agt flag to true since an agent is signing the payload
    , "uid": doc_uid
    , "len": len(body_b64)
    , "sha": calculate_tsrct_sha256(body_b64)
    , "sig": body_sig # Put the body signature inside the header
    , "acl": "acl_pub"
  }

  if description:
    header_data["dsc"] = description

  # 4. Build and Sign T-Doc
  tdoc = TDoc(header=TDocHeader(**header_data), body_b64=body_b64)
  header_b64 = b64url_encode(tdoc.header.model_dump_json(by_alias=True, exclude_none=True).encode('utf-8'))
  sign_input = f"{header_b64}.{tdoc.body_b64}".encode('utf-8')
  tdoc.signature_b64 = AGENT_SIG_CRYPTO.sign(sign_input)

  tdoc_str = tdoc.encode()
  log(f"[*] Created T-Doc (len {len(tdoc_str)})")

  # 5. Publish to API '/' root endpoint
  async with httpx.AsyncClient(timeout=10.0) as client:
    try:
      log(f"[*] Posting T-Doc to API root...")
      response = await client.post(
        f"{API_BASE_URL}/"
        , content=tdoc_str
        , headers={"Content-Type": "text/plain"}
      )
      response.raise_for_status()
      log("[*] T-Doc published successfully.")
      return json.dumps({
        "status": "PUBLISHED"
        , "uid": doc_uid
        , "sha": tdoc.header.sha
        , "tdoc_raw": tdoc_str
      }, indent=2)
    except Exception as e:
      log(f"[!] Error publishing T-Doc: {str(e)}")
      return f"Error publishing T-Doc: {str(e)}"

@mcp.tool()
async def publish_image_file(file_path: str, description: Optional[str] = "Signed image T-Doc from MCP") -> str:
  """
  Reads a local image file (PNG/JPG), signs it, and publishes it onto the tsrct ledger as a secure 'cls:doc', 'typ:blob' T-Doc.
  """
  await ensure_authorized()
  log(f"[*] Tool called: publish_image_file(path='{file_path}')")

  if not os.path.exists(file_path):
    return f"Error: Image file not found at {file_path}"

  # 1. Determine Content-Type based on extension
  ext = os.path.splitext(file_path)[1].lower()
  if ext == ".png":
    cty_field = "image/png"
  elif ext in [".jpg", ".jpeg"]:
    cty_field = "image/jpeg"
  else:
    return f"Error: Unsupported image format {ext} (must be .png or .jpg)"

  # 2. Read file and encode in base64url
  with open(file_path, "rb") as f:
    img_bytes = f.read()
  
  body_b64 = b64url_encode(img_bytes)
  doc_uid = f"{AGENT_UID}.{uuid.uuid4()}"
  now_epoch = int(time.time())
  its_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

  # Calculate body signature (sig) generated over the Base64 body string
  body_sig = AGENT_SIG_CRYPTO.sign(body_b64.encode('utf-8'))

  # 3. Construct the mandatory Header Fields
  header_data = {
    "alg": "RS256"
    , "cls": "doc"
    , "typ": "blob"
    , "cty": cty_field
    , "its": its_iso
    , "nce": now_epoch
    , "src": AGENT_SRC
    , "key": AGENT_UID
    , "agt": True
    , "uid": doc_uid
    , "len": len(body_b64)
    , "sha": calculate_tsrct_sha256(body_b64)
    , "sig": body_sig
    , "acl": "acl_pub"
  }

  if description:
    header_data["dsc"] = description

  # 4. Build and Sign T-Doc
  tdoc = TDoc(header=TDocHeader(**header_data), body_b64=body_b64)
  header_b64 = b64url_encode(tdoc.header.model_dump_json(by_alias=True, exclude_none=True).encode('utf-8'))
  sign_input = f"{header_b64}.{tdoc.body_b64}".encode('utf-8')
  tdoc.signature_b64 = AGENT_SIG_CRYPTO.sign(sign_input)

  tdoc_str = tdoc.encode()

  # 5. Publish to local/prod API endpoint
  async with httpx.AsyncClient(timeout=30.0) as client:
    try:
      response = await client.post(
        f"{API_BASE_URL}/"
        , content=tdoc_str
        , headers={"Content-Type": "text/plain"}
      )
      response.raise_for_status()
      return json.dumps({
        "status": "PUBLISHED"
        , "uid": doc_uid
        , "sha": tdoc.header.sha
        , "explorer_url": f"http://localhost:5173/{doc_uid}" if "localhost" in API_BASE_URL else f"https://tsrct.io/{doc_uid}"
      }, indent=2)
    except Exception as e:
      return f"Error publishing T-Doc: {str(e)}"

@mcp.tool()
async def get_tdoc_header(uid: str) -> str:
  """
  Fetches the registered T-Doc header for a given UID from the API.
  """
  log(f"[*] Tool called: get_tdoc_header(uid='{uid}')")
  async with httpx.AsyncClient(timeout=10.0) as client:
    try:
      response = await client.get(f"{API_BASE_URL}/{uid}")
      response.raise_for_status()
      header_data = response.json()
      return json.dumps(header_data, indent=2)
    except httpx.HTTPStatusError as e:
      return f"Error: API returned status code {e.response.status_code}. Detail: {e.response.text}"
    except Exception as e:
      return f"Error fetching T-Doc header: {str(e)}"

@mcp.tool()
async def get_full_tdoc(uid: str) -> str:
  """
  Fetches the full raw T-Doc string for a given UID from the API.
  """
  log(f"[*] Tool called: get_full_tdoc(uid='{uid}')")
  async with httpx.AsyncClient(timeout=10.0) as client:
    try:
      response = await client.get(f"{API_BASE_URL}/{uid}/tdoc")
      response.raise_for_status()
      return response.text
    except httpx.HTTPStatusError as e:
      return f"Error: API returned status code {e.response.status_code}. Detail: {e.response.text}"
    except Exception as e:
      return f"Error fetching full T-Doc: {str(e)}"

@mcp.tool()
async def get_tdoc_body(uid: str) -> str:
  """
  Fetches the decrypted/decoded T-Doc body for a given UID from the API.
  Handles any content type (JSON, text, images, octet streams) based on headers.
  """
  log(f"[*] Tool called: get_tdoc_body(uid='{uid}')")
  async with httpx.AsyncClient(timeout=10.0) as client:
    try:
      response = await client.get(f"{API_BASE_URL}/{uid}/body")
      response.raise_for_status()
      
      content_type = response.headers.get("content-type", "application/octet-stream").lower()
      log(f"[*] Retrieved content type: {content_type}")

      # 1. Handle JSON
      if "application/json" in content_type:
        try:
          body_data = response.json()
          return json.dumps(body_data, indent=2)
        except Exception:
          return response.text

      # 2. Handle Images
      elif "image/" in content_type:
        img_bytes = response.content
        img_b64 = base64.b64encode(img_bytes).decode('utf-8')
        return (
          f"### Decoded T-Doc Body (Image: {content_type})\n\n"
          f"![T-Doc Image](data:{content_type};base64,{img_b64})"
        )

      # 3. Handle Text
      elif "text/" in content_type:
        return response.text

      # 4. Handle Binary/Octet-Stream and other formats
      else:
        binary_bytes = response.content
        binary_b64 = base64.b64encode(binary_bytes).decode('utf-8')
        return (
          f"### Decoded T-Doc Body (Binary Stream: {content_type})\n"
          f"Length: {len(binary_bytes)} bytes\n\n"
          f"Base64 Payload:\n{binary_b64}"
        )

    except httpx.HTTPStatusError as e:
      return f"Error: API returned status code {e.response.status_code}. Detail: {e.response.text}"
    except Exception as e:
      return f"Error fetching T-Doc body: {str(e)}"

@mcp.tool()
async def validate_tdoc(tdoc_raw: Optional[str] = None, uid: Optional[str] = None) -> str:
  """
  Validates a raw T-Doc string or fetches and validates a registered T-Doc by UID.
  Checks both SHA-256 body integrity and the RS256 signature against the retrieved key.
  """
  log(f"[*] Tool called: validate_tdoc(tdoc_raw={'provided' if tdoc_raw else 'None'}, uid={uid})")
  
  if not tdoc_raw and not uid:
    return "Error: You must provide either 'tdoc_raw' or a registered T-Doc 'uid' to validate."

  async with httpx.AsyncClient(timeout=10.0) as client:
    # 1. Fetch raw T-Doc if UID is provided
    if uid:
      try:
        log(f"[*] Fetching T-Doc for UID {uid}...")
        response = await client.get(f"{API_BASE_URL}/{uid}/tdoc")
        response.raise_for_status()
        tdoc_raw = response.text.strip()
      except Exception as e:
        return f"Error fetching T-Doc from API: {str(e)}"

    # 2. Parse T-Doc parts (header.body.signature)
    parts = tdoc_raw.split('.')
    if len(parts) != 3:
      return f"Error: Invalid T-Doc format. Expected 3 dot-separated parts, got {len(parts)} parts."

    header_b64, body_b64, signature_b64 = parts[0], parts[1], parts[2]

    # 3. Decode and parse Header
    try:
      # Fix padding for decoding
      missing_padding = len(header_b64) % 4
      header_padded = header_b64 + ('=' * (4 - missing_padding) if missing_padding else '')
      header_json = base64.urlsafe_b64decode(header_padded).decode('utf-8')
      header = json.loads(header_json)
    except Exception as e:
      return f"Error: Failed to decode or parse T-Doc header: {str(e)}"

    report = {
      "uid": header.get("uid")
      , "cls": header.get("cls")
      , "typ": header.get("typ")
      , "src": header.get("src")
      , "sha_check": "FAILED"
      , "sig_check": "FAILED"
      , "details": []
    }

    # 4. Verify SHA-256 Quirk
    # sha = SHA-256(UTF8-Bytes(body_b64))
    header_sha = header.get("sha")
    if not header_sha:
      report["details"].append("Validation failed: Header is missing 'sha' field.")
    else:
      computed_sha = calculate_tsrct_sha256(body_b64)
      if computed_sha == header_sha:
        report["sha_check"] = "PASSED"
        report["details"].append("Body integrity (SHA-256) matches header 'sha'.")
      else:
        report["details"].append(f"Body integrity mismatch: Header 'sha' is '{header_sha}', but computed '{computed_sha}'.")

    # 5. Fetch Public Signing Key (/{key}/body)
    signing_key_id = header.get("key")
    if not signing_key_id:
      report["details"].append("Signature verification skipped: Header is missing 'key' field.")
      return json.dumps(report, indent=2)

    try:
      log(f"[*] Fetching signing key {signing_key_id} from API...")
      key_response = await client.get(f"{API_BASE_URL}/{signing_key_id}/body")
      key_response.raise_for_status()
      jwk_set = key_response.json()
      
      # Handle both JWKS (array) or single JWK
      jwk = None
      if "keys" in jwk_set:
        # Find the signature key
        for k in jwk_set["keys"]:
          if k.get("use") == "sig":
            jwk = k
            break
        if not jwk and jwk_set["keys"]:
          jwk = jwk_set["keys"][0]
      else:
        jwk = jwk_set

      if not jwk:
        report["details"].append(f"Signature verification failed: No signature key found in JWKS for {signing_key_id}.")
        return json.dumps(report, indent=2)

    except Exception as e:
      report["details"].append(f"Signature verification failed: Error fetching public key {signing_key_id}: {str(e)}.")
      return json.dumps(report, indent=2)

    # 6. Verify RS256 Signature over bytes of: header_b64 + "." + body_b64
    sign_input = f"{header_b64}.{body_b64}".encode('utf-8')
    sig_verified = CryptoManager.verify_signature(jwk, sign_input, signature_b64)
    
    if sig_verified:
      report["sig_check"] = "PASSED"
      report["details"].append("Cryptographic signature (RS256) verified successfully.")
    else:
      report["details"].append("Cryptographic signature (RS256) verification failed.")

    return json.dumps(report, indent=2)

if __name__ == "__main__":
  mcp.run()
