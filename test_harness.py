import subprocess
import json
import sys
import os
import time

def send_rpc(proc, method, params=None):
  request = {
    "jsonrpc": "2.0"
    , "id": int(time.time() * 1000)
    , "method": method
  }
  if params:
    request["params"] = params
  
  msg = json.dumps(request) + "\n"
  proc.stdin.write(msg)
  proc.stdin.flush()
  return msg

def read_rpc(proc):
  while True:
    line = proc.stdout.readline()
    if not line:
      # Check stderr if stdout is empty
      err = proc.stderr.readline()
      if err:
        print(f"[ERR] {err.strip()}")
        continue
      return None
    
    # If it doesn't look like JSON, it might be a print statement
    if not line.strip().startswith("{"):
      print(f"[*] Server Output: {line.strip()}")
      continue
      
    return json.loads(line)

def main():
  env = os.environ.copy()
  env["TSRCT_DEV"] = "true"
  env["PYTHONPATH"] = "."
  
  # Ensure we start fresh for the test
  if os.path.exists("identity.json"):
    os.remove("identity.json")

  print("[*] Starting MCP Server in DEV mode...")
  # Use the venv python if possible, otherwise system python
  python_exe = "./.venv/bin/python3" if os.path.exists("./.venv/bin/python3") else "python3"
  
  proc = subprocess.Popen(
    [python_exe, "server.py"]
    , stdin=subprocess.PIPE
    , stdout=subprocess.PIPE
    , stderr=subprocess.PIPE
    , text=True
    , env=env
  )

  try:
    # 1. Initialize
    print("[*] Sending 'initialize'...")
    send_rpc(proc, "initialize", {
      "protocolVersion": "2024-11-05"
      , "capabilities": {}
      , "clientInfo": {"name": "test-harness", "version": "1.0"}
    })
    
    # Read response (could be multiple if there are log messages)
    while True:
      resp = read_rpc(proc)
      if not resp: break
      print(f"[<] {json.dumps(resp, indent=2)}")
      if "result" in resp: break

    # Check if identity.json was created
    time.sleep(2) # Give it a moment to finish initialize_identity
    if os.path.exists("identity.json"):
      with open("identity.json", "r") as f:
        id_data = json.load(f)
        print(f"[!] Identity created: {id_data['uid']}")
    else:
      print("[!] Error: identity.json was not created.")
      # Check stderr
      stderr_output = proc.stderr.read()
      if stderr_output:
        print(f"[!] Stderr: {stderr_output}")
      return

    # 2. Call propose_agent_registration
    print("[*] Calling 'propose_agent_registration'...")
    send_rpc(proc, "tools/call", {
      "name": "propose_agent_registration"
      , "arguments": {"agent_name": "TestHarnessAgent"}
    })
    
    while True:
      resp = read_rpc(proc)
      if not resp: break
      print(f"[<] {json.dumps(resp, indent=2)}")
      if "result" in resp: break

  finally:
    proc.terminate()
    print("[*] Test harness finished.")

if __name__ == "__main__":
  main()
