import sqlite3
from DB import db_init, display_db, clear_db
import secrets
import time
import os
from constants import HASH_ID_SERVER_KEY, HASH_TOKEN_SERVER_KEY
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ciphers
import hmac

"""
HMAC of user id is deterministic and protects user's privacy
attacker should not infer relationships between voter and candidate they voted for
attacker should not know who and how many people have voted/not voted yet 
attacker should not know how many votes each candidate has so far

use a single key per table, but encrypt each row with a unique random nonce.
store both the nonce and ciphertext.

"""

"""
If an attacker (or a curious admin, or side-channel observer) monitors:
Which rows are accessed (even though encrypted)

When they’re accessed

How often they’re updated

They can infer:

Which candidate is receiving votes (from frequency of updates)

Who voted and when

Correlate time of access with external observations
"""

# # CLEAR DATABASE
# clear_db()

# # INITIALIZE DATABASE
# db_init()

# SHOW DATABASE - encrypted
display_db()

print("\n---------------------------------------------------------------\n")

# SHOW DATABASE - decrypted (candidates and ids)
# Connect to database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute("SELECT * FROM Candidates")
rows = cursor.fetchall()
print("Candidates table:")
for row in rows:
    name, votes, nonce = row
    votes = int(ciphers.candidates_cipher.decrypt(nonce, votes, f"candidates_table,name={name}".encode()).decode())
    print(name, votes, nonce)


cursor.execute("SELECT * FROM Ids")
rows = cursor.fetchall()
print("Ids table:")
for row in rows:
    id_hash, voted, otp, expire_time, nonce = row

    voted = ciphers.ids_cipher.decrypt(nonce, voted, f"ids_table,hash={id_hash}".encode()).decode()
    otp = ciphers.ids_cipher.decrypt(nonce, otp, f"ids_table,hash={id_hash}".encode()).decode()
    expire_time = int(ciphers.ids_cipher.decrypt(nonce, expire_time, f"ids_table,hash={id_hash}".encode()).decode())

    print(id_hash, voted, otp, expire_time, nonce)



# print(ciphers.candidates_nonces)
# print(ciphers.ids_nonces)
# k = AESGCM.generate_key(128)
# cipher = AESGCM(k)
# nonce = os.urandom(12)
# cipher_text = cipher.encrypt(nonce, b'0', b'data to authenticate')
# print(d.decode())
