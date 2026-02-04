import sys
sys.stdout.flush()
import logging

import hvac

LOGFILE = "/tmp/ret_key.log"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(LOGFILE)
file_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Optional: Log to stdout as well
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)

class VaultConnectionError(RuntimeError):
    pass

logger.info("Starting retrieval of encryption key from Vault")

def get_encryption_key(username=None) -> str:
    logger.info("Initializing Vault client for user '%s'", username if username else "default   client")
    try:
        if username == None:
            client = hvac.Client(
                url="https://vault.local:8200",
                cert=(
                    "/etc/vault-client/client.pem",
                    "/etc/vault-client/client.key"
                ),
                verify="/etc/vault-client/ca.pem"
            )
        else:
            print(f"Looking for client certs in /etc/vault-client/{username}/")
            client = hvac.Client(
                url="https://vault.local:8200",
                cert=(
                    f"/etc/vault-client/{username}/{username}.pem",
                    f"/etc/vault-client/{username}/{username}.key"
                ),
                verify=f"/etc/vault-client/{username}/vault-server-ca.pem"
            )    
    except Exception as e:
        logging.error(f"Error initializing Vault client: {e}")
        raise VaultConnectionError(f"Failed to initialize Vault client: {e}")
    
    client.auth.cert.login()
    
    logger.info("Client token: %s", client.token)
    logger.info("Is authenticated: %s", client.is_authenticated())

    logger.info("Attempting to authenticate to Vault using AppRole")

    if not client.is_authenticated():
        logging.error("Vault authentication failed")
        raise VaultConnectionError("Failed to authenticate to Vault")
    
    try:
        secret = client.secrets.kv.v2.read_secret_version(
            mount_point="secret",
            path="encryption-key"
        )
    except hvac.exceptions.VaultError as e:
        logging.error(f"Error retrieving secret from Vault: {e}")
        raise VaultConnectionError(f"Failed to retrieve encryption key: {e}")
    
    # Navigate the secret structure to get the actual key
    try:
        key = secret["data"]["data"]["key"]
    except (KeyError, TypeError) as e:
        logging.error(f"Malformed secret structure: {e}")
        raise VaultConnectionError("Encryption key missing or malformed in Vault")
    
    if not key or not isinstance(key, str):
        logging.error("Encryption key is empty or invalid")
        raise VaultConnectionError("Encryption key is empty or invalid")
    
    logging.info("Successfully retrieved encryption key from Vault")
    return key
