from retrieve_key import get_encryption_key
from file_encrypt import encrypt_file
from cryptography import fernet
from pathlib import Path
from config import EXTENSION_LIST

import logging
import argparse
import base64
import getpass

BASEDIR="/media/mike/58f427b0-3b57-4efa-a998-0092fe6dcdab/"
extension_list = EXTENSION_LIST
excluded_dirs = {'My Pictures','Documents','Desktop','mozilla','player','Music','lost+found','.mozilla'}
username = getpass.getuser()

logging.basicConfig(filename="/tmp/encrypt.log",level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")

if username == "root":
    logging.error("Script is being run as root user, exiting for safety")
    raise RuntimeError("Script should not be run as root user")

def is_excluded(path: Path) -> bool:
    logging.debug(f"Checking if path is excluded: {path}")
    return any(part in excluded_dirs for part in path.parts)

def encrypt_files(root_dir=None):
    # Check if parameter is passed to root_dir)
    basedir = Path(root_dir) if root_dir is not None else Path(BASEDIR)

    basedir = basedir.resolve()

    if not basedir.is_dir():
        raise ValueError(f"{basedir} is not a valid directory")
    
    # Safety Guard
    if basedir == Path("/"):
        raise RuntimeError("Invalid starting dir, root filesystem protected")

    raw_key = get_encryption_key(username).strip() # in memory only
    key = base64.urlsafe_b64decode(raw_key)
    logging.info(f"Encryption key retrieved successfully with value: {key[:4]}...{key[-4:]}  (length: {len(key)})") 

    # Create a fernet object using the key
    # fernetEncryptionKey = fernet.Fernet(key)

    for path in basedir.rglob('*'):
        logging.info(f"Processing file: {path}")
        try:
            if (
                not path.is_file()
                or path.is_symlink()
                or is_excluded(path)
                or path.suffix.lower() not in extension_list
            ):
                continue
            
            logging.info(f"Encrypting file: {path}")
            encrypt_file(path, key, extension_list)
        
        except PermissionError as e:
            logging.warning("Skipping (permission denied): {path}")
            continue

        except OSError as e:
            # Catch other filesystem errors without stopping
            logging.warning(f"Skipping {path}: {e}")
            continue

    del key
    # del fernetEncryptionKey

def main(dry_run=False, root_dir=None):
    
    if dry_run:
        print("Dry run mode: No files will be encrypted.")
        logging.info("Starting encryption process, fetching encryption key from Vault")
        key = get_encryption_key()
        logging.info("Encryption key retrieved successfully with value: {key[:4]}...{key[-4:]}  (length: {len(key)})")
        return 0

    encrypt_files(root_dir=root_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--root-dir")

    args = parser.parse_args()
    main(dry_run=args.dry_run, root_dir=args.root_dir)
   
