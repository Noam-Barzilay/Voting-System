import constants
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import base64

def generate_keys():
    # store keys in .env file
    with open(".env", "w") as f:
        for id in constants.ids:

            # server key to calculate id hmac
            hmac_key = secrets.token_bytes(32)

            # server key to encrypt/decrypt id table row
            aes_key =  AESGCM.generate_key(128)

            f.write(f"{id}_HMAC_KEY={base64.b64encode(hmac_key).decode()}\n")
            f.write(f"{id}_AES_KEY={base64.b64encode(aes_key).decode()}\n")

        # generate server key to calculate tokens hmacs
        f.write(f"HMAC_TOKEN_SERVER_KEY={base64.b64encode(secrets.token_bytes(32)).decode()}\n")

        # server key to encrypt/decrypt candidates table rows
        f.write(f"CANDIDATES_CIPHER_KEY={base64.b64encode(AESGCM.generate_key(128)).decode()}\n")
