import json
import os
import sys

# Add the current directory to sys.path to import crypto
sys.path.append(os.getcwd())

from crypto import CryptoManager

def main():
    if not os.path.exists("identity.json"):
        print("Error: identity.json not found.")
        return

    with open("identity.json", "r") as f:
        data = json.load(f)
        sig_crypto = CryptoManager(data["sig_private_key"].encode('utf-8'))
        enc_crypto = CryptoManager(data["enc_private_key"].encode('utf-8'))
        
        jwks = sig_crypto.get_jwks_set(enc_crypto)
        print(json.dumps(jwks, indent=2))

if __name__ == "__main__":
    main()
