from constants import CANDIDATES_CIPHER_KEY, IDS_CIPHER_KEY
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
candidates_cipher = AESGCM(CANDIDATES_CIPHER_KEY)
ids_cipher = AESGCM(IDS_CIPHER_KEY)
