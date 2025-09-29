import sqlite3
import constants
import hmac
import hashlib
import constants
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
import base64

# encrypt all database (besides hash value of id)
# never reuse the same nonce with the same key, but store the nonce publicly
# with each enryption to insert/update database - generate new nonce and encrypt all row back (besides hash)


def db_init():
    load_dotenv()
    # Connect to database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Create Candidates table
    # (candidate, number of votes they got, nonce)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Candidates (
        name TEXT PRIMARY KEY,
        votes INT,
        nonce TEXT
    )
    """)

    # create cipher
    aes_key = base64.b64decode(os.getenv("CANDIDATES_CIPHER_KEY"))
    candidates_cipher = AESGCM(aes_key)

    # create the rows in Candidates
    for name in constants.candidates:
        nonce = os.urandom(12)

        # customized candidate tag
        # votes need to be casted to int after decryption
        encrypted_votes = candidates_cipher.encrypt(nonce, b'0', f"candidates_table,name={name}".encode())

        # Insert data - use (?, ?) to avoid sql injection - handled by sqlite
        cursor.execute("INSERT INTO Candidates (name, votes, nonce) VALUES (?, ?, ?)", (name, encrypted_votes, nonce))
        conn.commit()


    # Create Ids table
    # (HMAC secure hash of user's id, voted (1 - yes, 0 - no), OTP, expire time of OTP, nonce)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Ids (
        id_hash TEXT PRIMARY KEY,
        voted char(1),
        OTP TEXT,
        expire_time INT,
        nonce TEXT
    )
    """)

    # create the rows in Ids
    for id_ in constants.ids:
        nonce = os.urandom(12)

        hmac_key = base64.b64decode(os.getenv(f"{id_}_HMAC_KEY"))

        id_hash = hmac.new(hmac_key, id_.encode(), hashlib.sha256).hexdigest()

        # create cipher
        aes_key = base64.b64decode(os.getenv(f"{id_}_AES_KEY"))
        user_cipher = AESGCM(aes_key)

        # customized user tag
        voted_encrypted = user_cipher.encrypt(nonce, b'0', f"ids_table,hash={id_hash}".encode())
        otp_encrypted = user_cipher.encrypt(nonce, b'dummy', f"ids_table,hash={id_hash}".encode())

        # expire_time need to be casted to int after decryption
        expire_time_encrypted = user_cipher.encrypt(nonce, b'00', f"ids_table,hash={id_hash}".encode())

        # Insert data - use (?) to avoid sql injection - handled by sqlite
        cursor.execute("INSERT INTO Ids (id_hash, voted, OTP, expire_time, nonce) VALUES (?, ?, ?, ?, ?)",
                        (id_hash, voted_encrypted, otp_encrypted, expire_time_encrypted, nonce))
        conn.commit()


    # Create tokens table
    # (token hash (HMAC), was the token used (1 - yes, 0 - no))
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Tokens (
        token_hash TEXT PRIMARY KEY,
        used char(1)
    )
    """)
    # when user grants access to voting system, generate token and give it to them
    # insert only then to this table

    conn.close()


def display_raw_db():
    # Connect to database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM Candidates")
    rows = cursor.fetchall()
    print("Candidates table:")
    for row in rows:
        print(*row)

    cursor.execute("SELECT * FROM Ids")
    rows = cursor.fetchall()
    print("Ids table:")
    for row in rows:
        print(*row)

    cursor.execute("SELECT * FROM Tokens")
    rows = cursor.fetchall()
    print("Tokens table:")
    for row in rows:
        print(*row)


    conn.close()

def display_decrypted_db():
    # SHOW DATABASE - decrypted (candidates and ids)
    
    load_dotenv()
    # Connect to database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM Candidates")
    rows = cursor.fetchall()
    print("Candidates table:")

    # get key and build cipher of candidates table
    aes_key = base64.b64decode(os.getenv("CANDIDATES_CIPHER_KEY"))
    candidate_cipher = AESGCM(aes_key)

    for row in rows:
        name, votes, nonce = row

        votes = int(candidate_cipher.decrypt(nonce, votes, f"candidates_table,name={name}".encode()).decode())
        print(name, votes, nonce)


    cursor.execute("SELECT * FROM Ids")
    rows = cursor.fetchall()
    print("Ids table:")

    for i in range(1, len(rows) + 1):
        id_hash, voted, otp, expire_time, nonce = rows[i-1]

        # get key and build cipher of candidates table
        aes_key = base64.b64decode(os.getenv(f"{i}_AES_KEY"))
        user_cipher = AESGCM(aes_key)

        voted = user_cipher.decrypt(nonce, voted, f"ids_table,hash={id_hash}".encode()).decode()
        otp = user_cipher.decrypt(nonce, otp, f"ids_table,hash={id_hash}".encode()).decode()
        expire_time = int(user_cipher.decrypt(nonce, expire_time, f"ids_table,hash={id_hash}".encode()).decode())

        print(id_hash, voted, otp, expire_time, nonce)


def clear_db():
    # Connect to database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS Candidates")
    conn.commit()
    cursor.execute("DROP TABLE IF EXISTS Ids")
    conn.commit()
    cursor.execute("DROP TABLE IF EXISTS Tokens")
    conn.commit()

    conn.close()
