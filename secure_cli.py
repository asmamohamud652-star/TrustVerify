import hashlib
import json
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class SecureCLI:
    def __init__(self):
        self.metadata_file = "metadata.json"
        self.signature_file = "signature.sig"
        self.private_key_file = "private_key.pem"
        self.public_key_file = "public_key.pem"
        self.script_file = os.path.basename(__file__)

    # --- STEP 1: KEY GENERATION ---
    def generate_keys(self):
        """Generate RSA public/private key pair."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open(self.private_key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(self.public_key_file, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"[SUCCESS] RSA Keys created: {self.private_key_file} & {self.public_key_file}")

    # --- STEP 2: HASH MANIFEST ---
    def generate_manifest(self, directory="."):
        """Scan directory and create metadata.json with file hashes."""
        manifest = {}
        excluded_files = {self.metadata_file, self.signature_file, self.private_key_file, self.public_key_file, self.script_file}

        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath) and filename not in excluded_files:
                manifest[filename] = self.get_file_hash(filepath)

        with open(self.metadata_file, "w") as f:
            json.dump(manifest, f, indent=4)
        print(f"[SUCCESS] Manifest created with file hashes in {self.metadata_file}")

    def get_file_hash(self, filepath):
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    # --- STEP 3: SIGNING ---
    def sign_manifest(self):
        if not os.path.exists(self.private_key_file):
            print("[ERROR] Private key missing. Run Step 1 first.")
            return

        with open(self.private_key_file, "rb") as key_file:
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
        print(f"[SUCCESS] Digital signature created: {self.signature_file}")

    # --- STEP 4: VERIFICATION ---
    def full_verify(self):
        # 1. Check if files were modified
        if not os.path.exists(self.metadata_file):
            print("[ERROR] metadata.json missing!")
            return

        with open(self.metadata_file, "r") as f:
            manifest = json.load(f)

        for filename, old_hash in manifest.items():
            if not os.path.exists(filename) or self.get_file_hash(filename) != old_hash:
                print(f"[ALERT] TAMPERING DETECTED: {filename} is modified or missing!")
                return

        # 2. Check if the signature is authentic
        try:
            with open(self.public_key_file, "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())
            with open(self.metadata_file, "rb") as f:
                manifest_data = f.read()
            with open(self.signature_file, "rb") as f:
                signature = f.read()

            public_key.verify(
                signature, manifest_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print("[SUCCESS] Integrity confirmed and Signature verified!")
        except Exception:
            print("[FAILED] Verification failed: Invalid signature or tampered manifest!")

# --- TERMINAL UI ---
if __name__ == "__main__":
    tool = SecureCLI()
    while True:
        print("\n--- TRUSTVERIFY STEP-BY-STEP ---")
        print("1. Generate RSA Keys")
        print("2. Generate File Manifest (Hashes)")
        print("3. Sign Manifest (Create Signature)")
        print("4. Full Verification Check")
        
        
        cmd = input("\nSelect Step: ").strip()
        if cmd == "1": tool.generate_keys()
        elif cmd == "2": tool.generate_manifest()
        elif cmd == "3": tool.sign_manifest()
        elif cmd == "4": tool.full_verify()
       
        else: print("Select 1-4.")