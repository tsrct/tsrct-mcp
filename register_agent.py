import asyncio
import os
import re
import sys
import httpx

# Ensure we are in the correct directory to import server
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def main():
  # Check if local API is running on 8080
  local_api_url = "http://localhost:8080"
  is_local = False
  async with httpx.AsyncClient() as client:
    try:
      response = await client.get(f"{local_api_url}/actuator/health", timeout=1.0)
      if response.status_code == 200:
        is_local = True
    except Exception:
      try:
        response = await client.get(local_api_url, timeout=1.0)
        is_local = True
      except Exception:
        pass

  if is_local:
    print("[*] Detected local tsrct API backend running on port 8080.")
    os.environ["TSRCT_DEV"] = "true"
    os.environ["TSRCT_API_URL"] = local_api_url
  else:
    print("[*] No local API backend detected. Using production tsrct API (https://api.tsrct.io).")
    os.environ["TSRCT_DEV"] = "false"
    os.environ["TSRCT_API_URL"] = "https://api.tsrct.io"

  # Import server after setting environment variables
  import server

  agent_name = "antigravity-local"
  agent_description = "Antigravity AI local pair programmer agent"

  print(f"[*] Proposing agent registration for '{agent_name}'...")
  result = await server.propose_agent_registration(agent_name, agent_description)
  print(result)

  # Extract session ID from the output
  match = re.search(r"Session ID: ([a-f0-9\-]+)", result)
  if not match:
    print("[!] Error: Could not find Session ID in the response.")
    sys.exit(1)

  session_id = match.group(1)
  print(f"\n[*] Extracted Session ID: {session_id}")
  print("[*] Starting registration polling. Please scan the QR code above with your mobile app to authorize the agent...")
  
  # Start polling
  polling_result = await server.wait_for_registration(session_id)
  print("\n" + "="*50)
  print(polling_result)
  print("="*50)

if __name__ == "__main__":
  asyncio.run(main())
