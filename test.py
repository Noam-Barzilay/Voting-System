import sqlite3
from DB_init import db_init
import pyotp
import time

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


conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# # CLEAR DATABASE
# cursor.execute("DROP TABLE IF EXISTS Candidates")
# conn.commit()
# cursor.execute("DROP TABLE IF EXISTS Ids")
# conn.commit()
# cursor.execute("DROP TABLE IF EXISTS Tokens")
# conn.commit()
# cursor.execute("DROP TABLE IF EXISTS Signatures")
# conn.commit()
# cursor.execute("DROP TABLE IF EXISTS Otps")
# conn.commit()

# # INITIALIZE DATABASE
# db_init()

# Show all rows
cursor.execute("SELECT * FROM Candidates")
rows = cursor.fetchall()
print("Candidates table:")
for row in rows:
    print(row)

# Show all rows
cursor.execute("SELECT * FROM Ids")
rows = cursor.fetchall()
print("Ids table:")
for row in rows:
    print(row)

# Show all rows
cursor.execute("SELECT * FROM Tokens")
rows = cursor.fetchall()
print("Tokens table:")
for row in rows:
    print(row)

# Show all rows
cursor.execute("SELECT * FROM Signatures")
rows = cursor.fetchall()
print("Signatures table:")
for row in rows:
    print(row)

"""
OTP treatment
"""
# secret_key = pyotp.random_base32()

# start_time = int(time.time())
# # Generate TOTP object based on the key - 10 digits to prevent brute force attack success
# totp = pyotp.TOTP(secret_key, digits=10)
# print(f"totp = {totp.now()}")

# user_input = input("Enter OTP: ")
# # Verify OTP entered by the user
# if pyotp.TOTP(secret_key).verify(user_input):
#     print("verified!")
