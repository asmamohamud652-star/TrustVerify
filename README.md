# TrustVerify

A Python CLI tool for file integrity and authenticity.

## How to use
1. Run `python secure_cli.py`
2. Select **Option 1** to generate keys and the metadata manifest.
3. Select **Option 2** to sign the manifest.
4. Select **Option 3** to verify file integrity and origin.

## Requirements
- `cryptography` library: `pip install cryptography`

## Security Note
- **Hashing:** Proves file integrity (detects tampering).
- **RSA Signing:** Proves authenticity (ensures the sender is authorized).
