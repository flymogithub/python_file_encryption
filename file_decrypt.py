from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import os
import base64
import re

IV_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 64 * 1024

def deobfuscate_filename(obfuscated_filename: str) -> str:
    """
    Decodes an obfuscated filename back to its original name,
    
    Args:
        obfuscated_filename(str): The obfuscated filename (e.g. 'ZG69jdW1lbnQ.txt')
    """
    if not obfuscated_filename or not isinstance(obfuscated_filename, str):
        return obfuscated_filename
    
    name,ext = os.path.splitext(obfuscated_filename)

    print(f"Deobfuscating filename: {obfuscated_filename}, name: {name}, ext: {ext}")
    
    # Base64 names should only contain urlsafe chars
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        print("Filename does not match Base64 urlsafe pattern.")
        return obfuscated_filename  # not base64 → not obfuscated

    # Add padding back for Base64 decoding
    padding = "=" * (-len(name) % 4)
    try:
        decoded_bytes = base64.urlsafe_b64decode(name + padding)
        decoded_str = decoded_bytes.decode(("utf8"))

        # Extra safety: decoded name must be sane
        if "/" in decoded_str or "\x00" in decoded_str:
            return obfuscated_filename
        
        print(f"Deobfuscated to: {decoded_str}{ext}")

        
    except (UnicodeDecodeError, ValueError):
        # Any failure = treat as not obfuscated
        print("Failed to decode Base64.")
        return obfuscated_filename

    return f"{decoded_str}{ext}"
        
    

def decrypt_file(enc_path, key):
    obfuscated_path = enc_path.with_suffix("").name # remove .enc
    print(f"Decrypting {obfuscated_path}...")
    original_name = deobfuscate_filename(obfuscated_path)
    out_path = enc_path.with_name(original_name)

    with open(enc_path, "rb") as f_in:
        iv = f_in.read(IV_SIZE)
        data = f_in.read()

    ciphertext = data[:-TAG_SIZE]
    tag = data[-TAG_SIZE:]

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend= default_backend()
    ).decryptor()

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag as e:
        print(f"Decryption failed for {enc_path}: Invalid authentication tag.")
        raise ValueError("Invalid authentication tag") from e

    with open(out_path, "wb") as f_out:
        f_out.write(plaintext)
    
    print(f"Decrypted to {out_path}")
    enc_path.unlink()  # remove the .enc file