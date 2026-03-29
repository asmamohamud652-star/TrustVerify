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

    # --- PART 1: HASHING & INTEGRITY ---

    def get_file_hash(self, filepath):
        """Generate SHA-256 hash for a file."""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def generate_manifest(self, directory="."):
        """Scan directory and create metadata.json with file hashes."""
        manifest = {}

        excluded_files = {
            self.metadata_file,
            self.signature_file,
            self.private_key_file,
            self.public_key_file,
            self.script_file
        }

        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath) and filename not in excluded_files:
                manifest[filename] = self.get_file_hash(filepath)

        with open(self.metadata_file, "w") as f:
            json.dump(manifest, f, indent=4)

        print(f"[*] Manifest created: {self.metadata_file}")

    def check_integrity(self, directory="."):
        """Compare current files against metadata.json."""
        if not os.path.exists(self.metadata_file):
            print("[!] metadata.json not found!")
            return False

        with open(self.metadata_file, "r") as f:
            manifest = json.load(f)

        excluded_files = {
            self.metadata_file,
            self.signature_file,
            self.private_key_file,
            self.public_key_file,
            self.script_file
        }

        # Check if original files still exist and match hashes
        for filename, old_hash in manifest.items():
            filepath = os.path.join(directory, filename)

            if not os.path.exists(filepath):
                print(f"[!] TAMPERING DETECTED: {filename} is missing!")
                return False

            current_hash = self.get_file_hash(filepath)
            if current_hash != old_hash:
                print(f"[!] TAMPERING DETECTED: {filename} has been modified!")
                return False

        # Optional: detect new unexpected files
        current_files = {
            filename for filename in os.listdir(directory)
            if os.path.isfile(os.path.join(directory, filename)) and filename not in excluded_files
        }

        manifest_files = set(manifest.keys())

        extra_files = current_files - manifest_files
        if extra_files:
            print(f"[!] WARNING: New unexpected files detected: {', '.join(extra_files)}")
            return False

        print("[+] Local integrity check passed.")
        return True

    # --- PART 2: RSA SIGNATURES ---

    def generate_keys(self):
        """Generate RSA public/private key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
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

        print(f"[*] Keys generated: {self.private_key_file} & {self.public_key_file}")

    def sign_manifest(self):
        """Sign metadata.json using private key."""
        if not os.path.exists(self.private_key_file):
            print("[!] Private key not found! Run setup first.")
            return

        if not os.path.exists(self.metadata_file):
            print("[!] metadata.json not found! Run setup first.")
            return

        with open(self.private_key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        with open(self.metadata_file, "rb") as f:
            manifest_data = f.read()

        signature = private_key.sign(
            manifest_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        with open(self.signature_file, "wb") as f:
            f.write(signature)

        print(f"[*] Manifest signed successfully: {self.signature_file}")

    def verify_origin(self):
        """Verify manifest signature using public key."""
        if not os.path.exists(self.public_key_file):
            print("[!] Public key not found!")
            return False

        if not os.path.exists(self.metadata_file):
            print("[!] metadata.json not found!")
            return False

        if not os.path.exists(self.signature_file):
            print("[!] signature.sig not found!")
            return False

        with open(self.public_key_file, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        with open(self.metadata_file, "rb") as f:
            manifest_data = f.read()

        with open(self.signature_file, "rb") as f:
            signature = f.read()

        try:
            public_key.verify(
                signature,
                manifest_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("[+] Signature verified: Origin is authentic.")
            return True
        except Exception:
            print("[!] VERIFICATION FAILED: Signature is invalid or manifest tampered!")
            return False


if __name__ == "__main__":
    tool = SecureCLI()

    print("\n--- TrustVerify CLI Tool ---")
    print("1. Setup (Generate Keys + Manifest)")
    print("2. Sign Manifest")
    print("3. Verify Integrity + Origin")

    choice = input("Select an option: ").strip()

    if choice == "1":
        tool.generate_keys()
        tool.generate_manifest(".")
    elif choice == "2":
        tool.sign_manifest()
    elif choice == "3":
        if tool.check_integrity("."):
            tool.verify_origin()
    else:
        print("[!] Invalid option selected.")