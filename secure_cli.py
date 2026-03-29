import hashlib
import json
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class SecureCLI:
    def __init__(self):
        self.metadata_file = "metadata.json"
        self.signature_file = "signature.sig"

    # --- PART 1: HASHING & INTEGRITY ---
    
    def get_file_hash(self, filepath):
        """Generates SHA-256 hash for a file."""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def generate_manifest(self, directory):
        """Scans directory and creates metadata.json with hashes."""
        manifest = {}
        for filename in os.listdir(directory):
            if os.path.isfile(filename) and filename not in [self.metadata_file, self.signature_file, "private_key.pem", "public_key.pem", "secure_cli.py"]:
                manifest[filename] = self.get_file_hash(filename)
        
        with open(self.metadata_file, "w") as f:
            json.dump(manifest, f, indent=4)
        print(f"[*] Manifest created in {self.metadata_file}")

    def check_integrity(self):
        """Compares current files against metadata.json."""
        if not os.path.exists(self.metadata_file):
            return False
        
        with open(self.metadata_file, "r") as f:
            manifest = json.load(f)
        
        for filename, old_hash in manifest.items():
            if not os.path.exists(filename):
                print(f"[!] Warning: {filename} is missing!")
                continue
            current_hash = self.get_file_hash(filename)
            if current_hash != old_hash:
                print(f"[!] TAMPERING DETECTED: {filename} has been modified!")
                return False
        print("[+] Local integrity check passed.")
        return True

    # --- PART 2: RSA SIGNATURES ---

    def generate_keys(self):
        """Generates RSA Public/Private key pair."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Save Private Key
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        # Save Public Key
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("[*] Keys generated: private_key.pem & public_key.pem")

    def sign_manifest(self):
        """Signs the metadata.json using the Private Key."""
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        with open(self.metadata_file, "rb") as f:
            manifest_data = f.read()

        signature = private_key.sign(
            manifest_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        with open(self.signature_file, "wb") as f:
            f.write(signature)
        print("[*] Manifest signed successfully.")

    def verify_origin(self):
        """Verifies the manifest signature using the Public Key."""
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        with open(self.metadata_file, "rb") as f:
            manifest_data = f.read()

        with open(self.signature_file, "rb") as f:
            signature = f.read()

        try:
            public_key.verify(
                signature,
                manifest_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print("[+] Signature Verified: Origin is authentic.")
            return True
        except Exception:
            print("[!] VERIFICATION FAILED: Signature is invalid or manifest tampered!")
            return False

# Quick CLI Logic
if __name__ == "__main__":
    tool = SecureCLI()
    print("--- Secure File CLI ---")
    print("1. Setup (Gen Keys & Manifest)\n2. Sign Manifest\n3. Verify Integrity & Origin")
    choice = input("Select an option: ")

    if choice == "1":
        tool.generate_keys()
        tool.generate_manifest(".")
    elif choice == "2":
        tool.sign_manifest()
    elif choice == "3":
        if tool.check_integrity():
            tool.verify_origin()