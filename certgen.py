#!/usr/bin/env python3

import os
import getpass
import hvac
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

VAULT_ADDR = os.environ.get("VAULT_ADDR")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN")

PKI_ROLE = "client"
CERT_TTL = "720h"

BASE_DIR = Path("/etc/vault-client")

def fail(msg):
    raise SystemExit(f"ERROR: {msg}")

def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

def generate_csr(key, common_name):
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name)
            ])
        )
        .sign(key, hashes.SHA256())
    )

def main():
    if not VAULT_ADDR or not VAULT_TOKEN:
        fail("VAULT_ADDR and VAULT_TOKEN must be set")

    username = getpass.getuser()
    client_dir = BASE_DIR / username
    client_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    key_path = client_dir / f"{username}.key"
    cert_path = client_dir / f"{username}.pem"
    ca_path = client_dir / "ca.pem"

    print(f"Bootstrapping Vault cert for user: {username}")

    # 1️⃣ Generate key + CSR
    key = generate_key()
    csr = generate_csr(key, username)

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    # 2️⃣ Connect to Vault
    client = hvac.Client(
        url=VAULT_ADDR,
        token=VAULT_TOKEN,
        verify="/etc/vault-client/ca.pem",
    )

    if not client.is_authenticated():
        fail("Vault authentication failed")

    # 3️⃣ Sign CSR
    response = client.secrets.pki.sign_certificate(
        name=PKI_ROLE,
        csr=csr_pem,
        common_name=username,
        mount_point="pki",
        extra_params={
            "ttl": CERT_TTL,
        },
    )

    cert_pem = response["data"]["certificate"]
    issuing_ca = response["data"]["issuing_ca"]

    # 4️⃣ Write files
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)

    cert_path.write_text(cert_pem)
    cert_path.chmod(0o644)

    ca_path.write_text(issuing_ca)
    ca_path.chmod(0o644)

    print("✔ Client certificate installed:")
    print(f"  Key:  {key_path}")
    print(f"  Cert: {cert_path}")
    print(f"  CA:   {ca_path}")
    print("✔ Bootstrap complete — switch to cert auth")

if __name__ == "__main__":
    main()
