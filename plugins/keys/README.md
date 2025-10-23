# 0xgen plugin signing keys

The `0xgen-plugin.pub` file contains the ECDSA P-256 public key used to verify
official plugin signatures. Maintain the corresponding private key in a secure
location; it should never be committed to the repository.

When rotating keys:

1. Generate a new key pair with `cosign generate-key-pair`.
2. Replace `0xgen-plugin.pub` with the new public key.
3. Re-sign each plugin artifact (`plugin.js`, `main.go`, etc.) with the updated
   private key.
4. Update the detached signature files referenced in `manifest.json`.
5. Submit the changes alongside an updated allowlist entry if the artifact
   contents changed.

0xgen's loader verifies both the SHA-256 hash (from `plugins/ALLOWLIST`) and the
cryptographic signature before executing a plugin.
