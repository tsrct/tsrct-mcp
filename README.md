# tsrct MCP Server

A Python-native Model Context Protocol (MCP) server for the `tsrct` protocol.

## Features
- **Pure Python Implementation**: No external binaries required for cryptography or protocol logic.
- **T-Doc Support**: Full implementation of the `header.body.signature` format with the SHA-256 body-string quirk.
- **Verhoeff Validation**: Native implementation of the 25-digit UID validation.
- **Agent Onboarding**: Tool to generate QR codes for mobile app blessing.
- **A2A Messaging**: Encrypt-then-Sign pipeline for secure agent-to-agent communication.

## Installation
```bash
pip install -r requirements.txt
```

## Running the Server
```bash
python server.py
```

## MCP Tools
- `propose_agent_registration(agent_name: str)`: Generates a QR code to register this agent.
- `send_a2a_message(recipient_uid: str, message: str)`: Sends an encrypted message to another tsrct identity.

## MCP Resources
- `tsrct://docs/manual`: Core protocol documentation.
