# tsrct MCP Server

A Python-native Model Context Protocol (MCP) server for the `tsrct` protocol.

## Features
- **Pure Python Implementation**: No external binaries required for cryptography or protocol logic.
- **T-Doc Support**: Full implementation of the `header.body.signature` format with the SHA-256 body-string quirk.
- **Verhoeff Validation**: Native implementation of the 25-digit UID validation.
- **Agent Onboarding**: Tool to generate QR codes for mobile app blessing.
- **A2A Messaging**: Encrypt-then-Sign pipeline for secure agent-to-agent communication.

## Setup
Before running or registering your MCP server, set up your end-user identity coordinates:
1. Download and install the **tsrct** mobile application on your mobile device.
2. Launch the app and create your decentralized cryptographic account.
3. Go to the credentials wallet within the app and add your primary identity card via **self-attestation** (attesting your name and title). This assigns you an active parent DDX authority record.
4. Once the MCP server has been successfully added to Gemini CLI or your preferred LLM host, prompt the AI agent to run `"propose agent registration"`. This initiates the deferred onboarding handshake, displaying a terminal QR code for you to scan with your mobile app and bless the local agent, permanently binding its cryptographic keys to your verified tsrct identity.

### Identity Storage & Security Coordinates
All local cryptographic keys (RS256 signing and RSA-OAEP encryption key pairs), user coordinates (`AGENT_SRC`), and authorized session identifiers are securely written and persisted locally inside your user home directory at:
```text
~/.tsrct/identity.json
```
This isolates your highly sensitive private keys away from the Git workspace to prevent accidental credential leakage, while allowing the `tsrct-mcp` server to automatically refer to, load, and sign transactions dynamically.

## Installation

For a fresh clone, set up a virtual environment and install the dependencies:

```bash
# Create a virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate  # On macOS/Linux

# Install requirements
pip install -r requirements.txt
```

## Running the Server

### Standalone (stdio)
You can run the server directly:

```bash
python server.py
```

### Integrating with Gemini CLI
To register this MCP server with Gemini CLI, run the following command from the workspace root:

```bash
gemini mcp add tsrct-mcp ./tsrct-mcp/.venv/bin/python ./tsrct-mcp/server.py
```

## MCP Resources

The following static/dynamic resources are exposed by the server to provide essential context and identity states to the LLM:

* **`tsrct://identity`**: Returns the current agent identity details (assigned UID, key ID, parent user UID, virtual ID, and persistence status).
  * *Usage Prompt:* "Show me my current tsrct agent identity status and details."
* **`tsrct://docs/manual`**: Retrieves the official tsrct system protocol manual (v1.0), specifying T-Doc format details, Verhoeff checksums, and schema constraints.
  * *Usage Prompt:* "Fetch the core tsrct protocol manual so we can review the document class schema."
* **`tsrct://docs/mcp-guide`**: Detailed operations guide on deferred onboarding, blessing handshakes, and cryptographic verification flows.
  * *Usage Prompt:* "Get the tsrct MCP integration and operations guide."

## MCP Tools

Below is a complete description of the cryptographic and transactional capabilities of this MCP server, along with the standard prompts to execute them:

### 1. Agent Onboarding & Registration
* **`propose_agent_registration(agent_name: str, agent_description: str)`**
  * *What it does:* Initiates the cryptographic blessing session on the tsrct ledger. It registers your local public keys (JWKS) and renders an ASCII QR code in your terminal.
  * *Usage Prompt:* "Register a new agent named 'my-agent' with the description 'Local development helper'."
* **`wait_for_registration(session_id: str)`**
  * *What it does:* Polls the authentication API until the user scans the QR code with their mobile app and authorizes the session. Saves the finalized identity into `identity.json`.
  * *Usage Prompt:* "Wait and poll for the registration session 'abc123xyz' to complete."

### 2. Document Creation & Publishing
* **`create_and_publish_tdoc(text: str, description: str, content_type: str, ddx_uid: str)`**
  * *What it does:* Creates, signs (RS256), and publishes a public/private `cls:doc` T-Doc onto the tsrct network. Supports optional real-time DDX credential countersigning handshakes.
  * *Usage Prompt:* "Publish a new text T-Doc containing 'Hello tsrct Network' with the description 'Greeting doc'."
* **`publish_image_file(file_path: str, description: str, ddx_uid: str)`**
  * *What it does:* Reads a local `.png` or `.jpg` file, encodes it as a base64url `typ:blob`, signs it, and publishes it onto the ledger.
  * *Usage Prompt:* "Publish the local image at './my-image.png' as a T-Doc and apply DDX 'ddx.example.uid'."

### 3. Messaging & Secure A2A Communication
* **`send_a2a_message(recipient_uid: str, message: str)`**
  * *What it does:* Sends an end-to-end encrypted message to another agent. Discovers their public encryption key, encrypts the payload, signs the ciphertext, and transmits the resulting private T-Doc.
  * *Usage Prompt:* "Send a secure message 'Top Secret payload' to the recipient '2345678901234567890123456'."
* **`send_target_message(recipient_uid: str, message: str, file_path: str, description: str)`**
  * *What it does:* Sends a secure, private, and non-listable T-Doc document specifically targeted to another recipient. Supports sending either standard text messages or rich files (images, PDFs, binary documents) provided via `file_path`. It guesses MIME types, encodes to Base64, sets target recipient ID in the `tgt` field, sets access control level to private (`acl:acl_pri`), and directory listing to false (`lst:false`). **Note: The target recipient *must* have the sender added as a contact (which they can easily do via the contacts section in their mobile app), otherwise the ledger API will reject the transmission.**
  * *Usage Prompt:* "Send a targeted private PDF document at './statement.pdf' with description 'Monthly Report' to recipient '2345678901234567890123456'."

### 4. Fetching & Querying
* **`get_user_documents()`**
  * *What it does:* Uses a signed `x-tsrct-auth` JWT to securely fetch all documents (including unlisted/private ones) registered under your user ID.
  * *Usage Prompt:* "Fetch all of my user's registered documents."
* **`get_my_recent_published_messages()`**
  * *What it does:* Fetch the most recently sent T-Doc messages securely from the API utilizing authentication JWT headers.
  * *Usage Prompt:* "Retrieve my recently published messages."
* **`get_user_recd_documents()`**
  * *What it does:* Fetches all T-Doc documents/messages where the authorized user is the recipient ('tgt' field matches the user's UID) securely using JWT authentication headers.
  * *Usage Prompt:* "Load and list all recent documents where I am the recipient."
* **`get_logged_in_user_ddxes(uid: str)`**
  * *What it does:* Fetches all valid active DDX credentials and entitlements currently assigned to the user or specified identity UID.
  * *Usage Prompt:* "Check what DDX entitlements are available for my user."

### 5. T-Doc Retrieval & Analysis
* **`get_tdoc_header(uid: str)`**
  * *What it does:* Retrieves only the JSON metadata header of a registered T-Doc by its UID.
  * *Usage Prompt:* "Fetch the T-Doc header for UID '12345.doc.abc123xyz'."
* **`get_full_tdoc(uid: str)`**
  * *What it does:* Retrieves the raw, single-line dot-separated T-Doc representation (`header.body.signature`).
  * *Usage Prompt:* "Get the full raw T-Doc string for '12345.doc.abc123xyz'."
* **`get_tdoc_body(uid: str)`**
  * *What it does:* Fetches the body, decodes the base64, and dynamically parses/renders it based on Content-Type (pretty-printed JSON, Markdown-embedded inline image, text, or hex-binary stream).
  * *Usage Prompt:* "Read and decode the body of the T-Doc '12345.doc.abc123xyz'."

### 6. Verification & Validation
* **`validate_tdoc(tdoc_raw: str, uid: str)`**
  * *What it does:* Performs comprehensive cryptographic validation of a local or fetched T-Doc string. It tests formatting, resolves the signer's JWKS, validates the SHA-256 body-string quirk hash, and verifies the RS256 signature locally.
  * *Usage Prompt:* "Validate the cryptographic signature and integrity of T-Doc '12345.doc.abc123xyz'."
