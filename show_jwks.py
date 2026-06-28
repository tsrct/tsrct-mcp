import json
import os

from tsrct_mcp.crypto import CryptoManager

def main():
    identity_file = os.path.expanduser("~/.tsrct/identity.json")
    if not os.path.exists(identity_file):
        print("Error: identity.json not found.")
        return

    with open(identity_file, "r") as f:
        data = json.load(f)
        sig_crypto = CryptoManager(data["sig_private_key"].encode('utf-8'))
        enc_crypto = CryptoManager(data["enc_private_key"].encode('utf-8'))
        
        jwks = sig_crypto.get_jwks_set(enc_crypto)
        print(json.dumps(jwks, indent=2))

if __name__ == "__main__":
    main()
