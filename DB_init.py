import sqlite3
import constants
import hmac
import hashlib
from constants import HASH_ID_SERVER_KEY


# TODO: need to encrypt all database (besides hash value of id)
# have a different key for each table

def db_init():
    # Connect to database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Create Candidates table
    # (candidate, number of votes they got)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Candidates (
        name TEXT PRIMARY KEY,
        votes INT
    )
    """)

    # create the rows in Candidates
    for name in constants.candidates:
        # Insert data - use (?, ?) to avoid sql injection - handled by sqlite
        cursor.execute("INSERT INTO Candidates (name, votes) VALUES (?, ?)", (name, 0))
        conn.commit()


    # Create Ids table
    # (HMAC secure hash of user's id, voted (1 - yes, 0 - no), OTP, expire time of OTP)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Ids (
        id_hash TEXT PRIMARY KEY,
        voted char(1),
        OTP TEXT,
        expire_time INT
    )
    """)

    # create the rows in Ids
    for id_ in constants.ids:
        # Insert data - use (?) to avoid sql injection - handled by sqlite
        cursor.execute("INSERT INTO Ids (id_hash, voted, OTP, expire_time) VALUES (?, ?, ?, ?)",
                        (hmac.new(HASH_ID_SERVER_KEY, id_.encode(), hashlib.sha256).hexdigest(), '0', "dummy", 0))
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

    # Create voting table
    # (token hash (HMAC), signature of confirming the voting)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Signatures (
        token_hash TEXT,
        signature TEXT,
        FOREIGN KEY (token_hash) REFERENCES Tokens(token_hash)
    )
    """)
    # after user votes, sign by their name with the systems private key by associating the token used

    conn.close()
