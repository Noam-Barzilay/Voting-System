import sqlite3
import webbrowser
import threading
from flask import Flask, render_template, request, redirect, url_for, jsonify
import hashlib
import time
import hmac
import secrets
from constants import INTERVAL_SIZE
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
import base64


app = Flask(__name__)
DB_FILE = 'database.db'

# function to generate token for voter's session
def generate_session_token():
    token = secrets.token_hex(32)
    return token  # 64-char


# root directory - start of app
@app.route('/')
def index():
    # log in screen
    return render_template('welcome_screen.html')


@app.route('/generate_otp', methods=['POST'])
def generate_otp():
    # generate otp regardless if user voted or not - adds a layer of protection against an adversary who has the id
    # of a user and wants to confirm this user voted - only valid otp will reveal that
    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400
    
    # connect and load db
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # get hmac key of id
    hmac_key = os.getenv(f"{user_id}_HMAC_KEY")

    # if id does not exist
    if hmac_key == None:
        return "Invalid id"

    hmac_key = base64.b64decode(hmac_key) 
    
    # search if id exists (based on hash)
    hashed_id = hmac.new(hmac_key, user_id.encode(), hashlib.sha256).hexdigest()
    
    # update if not present
    cursor.execute("SELECT * FROM Ids WHERE id_hash=(?)", (hashed_id,))
    Otp_row = cursor.fetchall()

    # if row does not exist in table
    if len(Otp_row) == 0:
        print("here")
        return "Invalid id"
    
    # get nonce
    nonce = Otp_row[0][4]

    # get key and build cipher of user based on the id
    aes_key = base64.b64decode(os.getenv(f"{user_id}_AES_KEY"))
    cipher = AESGCM(aes_key)

    # decrypt voted
    voted = cipher.decrypt(nonce, Otp_row[0][1], f"ids_table,hash={hashed_id}".encode())

    # generate otp
    expire_time = int(time.time()) + INTERVAL_SIZE  # valid for INTERVAL_SIZE seconds
    otp = str(secrets.randbelow(10**10)).zfill(10)  # 10-digit random OTP

    # create new nonce
    nonce = os.urandom(12)

    # encrypt new values and voted too
    voted_encrypted = cipher.encrypt(nonce, voted, f"ids_table,hash={hashed_id}".encode())
    otp_encrypted = cipher.encrypt(nonce, otp.encode(), f"ids_table,hash={hashed_id}".encode())
    encrypted_expire_time = cipher.encrypt(nonce, str(expire_time).encode(), f"ids_table,hash={hashed_id}".encode())

    # update otp and expire time
    cursor.execute("UPDATE Ids SET voted = (?), otp = (?), expire_time = (?), nonce = (?) WHERE id_hash = (?)",
                    (voted_encrypted, otp_encrypted, encrypted_expire_time, nonce, hashed_id,))
    conn.commit()
    cursor.close()
    

    # Return OTP (realistically send it via email/SMS)
    # jsonify returns a response object to the javascript script the called this api
    return jsonify({"otp": otp})


@app.route('/sign_in', methods=['POST'])
def sign_in():
    # retrieve user choice
    user_id = request.form['user_id']
    user_otp = request.form['user_otp']

    # connect and load db
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # get hmac key of id
    hmac_key = os.getenv(f"{user_id}_HMAC_KEY")
    
    # if id does not exist
    if hmac_key == None:
        return "Invalid id"
    
    hmac_key = base64.b64decode(hmac_key)
    
    # search for the corresponding row
    hashed_id = hmac.new(hmac_key, user_id.encode(), hashlib.sha256).hexdigest()
    cursor.execute("SELECT * FROM Ids WHERE id_hash=(?)", (hashed_id,))
    ids_rows = cursor.fetchall()

    if len(ids_rows) == 0:
        return "Invalid id"

    # retieve otp information
    _, voted, otp, expire_time, nonce = ids_rows[0]

    # get key and build cipher of user based on the id
    aes_key = base64.b64decode(os.getenv(f"{user_id}_AES_KEY"))
    cipher = AESGCM(aes_key)

    # decrypt
    otp = cipher.decrypt(nonce, otp, f"ids_table,hash={hashed_id}".encode()).decode()
    expire_time = int(cipher.decrypt(nonce, expire_time, f"ids_table,hash={hashed_id}".encode()).decode())

    # get cur time stamp
    current_time = int(time.time())

    # compare otps and make sure interval has not passed yet
    if current_time >= expire_time or user_otp != otp:
        return "Invalid OTP"

    did_vote = cipher.decrypt(nonce, voted, f"ids_table,hash={hashed_id}".encode()).decode()
        
    # if voter have not voted yet, procceed
    if did_vote == '0':
        conn.close()
        return redirect(url_for('get_token', user_id=user_id))
    else:
        return "You have already voted!"
    

@app.route('/get_token/<user_id>', methods=['GET', 'POST'])
def get_token(user_id):
    if request.method == "POST":
        return redirect(url_for('vote', user_id=user_id))

    else:  # GET request
        # connect and load db
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # generate token upon authentication
        token_rows, generated_token, hashed_token = [0], "", ""

        # get hmac key of token
        hmac_token = base64.b64decode(os.getenv("HMAC_TOKEN_SERVER_KEY"))

        # while generated token is already in table, generate a new one
        while (len(token_rows) > 0):
            # generate random token
            generated_token = generate_session_token()
            hashed_token = hmac.new(hmac_token, generated_token.encode(), hashlib.sha256).hexdigest()
            cursor.execute("SELECT * FROM Tokens WHERE token_hash=(?)", (hashed_token,))
            token_rows = cursor.fetchall()

        # update DB 
        # insert into tokens table
        #TODO: maybe encrypt used
        cursor.execute("INSERT INTO Tokens (token_hash, used) VALUES (?, ?)", (hashed_token, '0'))
        conn.commit()
        
        conn.close()
        return render_template('token_screen.html', user_id=user_id, generated_token=generated_token)


@app.route('/vote/<user_id>', methods=['GET', 'POST'])
def vote(user_id):
    # connect and load db
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # if we post data
    if request.method == "POST":
        
        # get hmac key of id
        hmac_key = os.getenv(f"{user_id}_HMAC_KEY")

        # if id does not exist
        if hmac_key == None:
            return "Invalid id"
        
        hmac_key = base64.b64decode(hmac_key)

        # check if user already voted - tried going back in the browser
        hashed_id = hmac.new(hmac_key, user_id.encode(), hashlib.sha256).hexdigest()
        cursor.execute("SELECT * FROM Ids WHERE id_hash=(?)", (hashed_id,))
        ids_rows = cursor.fetchall()
        
        # decrypt
        _, voted, otp, expire_time, ids_nonce = ids_rows[0]

        # get key and build cipher of user based on the id
        aes_key = base64.b64decode(os.getenv(f"{user_id}_AES_KEY"))
        user_cipher = AESGCM(aes_key)

        did_vote = user_cipher.decrypt(ids_nonce, voted, f"ids_table,hash={hashed_id}".encode()).decode()
        otp = user_cipher.decrypt(ids_nonce, otp, f"ids_table,hash={hashed_id}".encode())
        expire_time = user_cipher.decrypt(ids_nonce, expire_time, f"ids_table,hash={hashed_id}".encode())
        
        if did_vote == '1':
            return "User already voted!"
        
        # retrieve user choice and token
        name = request.form['option']
        token = request.form['token']

        # get hmac key of token
        hmac_token = base64.b64decode(os.getenv("HMAC_TOKEN_SERVER_KEY"))

        # make sure token is not used yet
        hashed_token = hmac.new(hmac_token, token.encode(), hashlib.sha256).hexdigest()
        cursor.execute("SELECT * FROM Tokens WHERE token_hash=(?)", (hashed_token,))
        token_rows = cursor.fetchall()

        if len(token_rows) > 0 and token_rows[0][1] == '1':
            return "Token already used"
        
        if len(token_rows) == 0:
            return "Invalid token"

        # find candidate information
        cursor.execute("SELECT * FROM Candidates WHERE name=(?)", (name,))
        candidate_rows = cursor.fetchall()

        name, votes, candidate_nonce = candidate_rows[0]

        # get key and build cipher of candidates table
        aes_key = base64.b64decode(os.getenv("CANDIDATES_CIPHER_KEY"))
        candidate_cipher = AESGCM(aes_key)

        # decrypt candidate's votes count
        candidate_votes = int(candidate_cipher.decrypt(candidate_nonce, votes, f"candidates_table,name={name}".encode()).decode())

        # update candidates table and encrypt back (increment candidate_votes)
        # create new nonce
        new_candidate_nonce = os.urandom(12)
        encrypted_votes = candidate_cipher.encrypt(new_candidate_nonce, str(candidate_votes+1).encode(),
                                                     f"candidates_table,name={name}".encode())
        cursor.execute("UPDATE Candidates SET votes = (?), nonce = (?) WHERE name=(?)",
                        (encrypted_votes, new_candidate_nonce, name,))
        conn.commit()

        # update that voter has voted and encrypt back
        # create new nonce
        new_ids_nonce = os.urandom(12)

        # encrypt all values in row
        voted_encrypted = user_cipher.encrypt(new_ids_nonce, b'1', f"ids_table,hash={hashed_id}".encode())
        otp_encrypted = user_cipher.encrypt(new_ids_nonce, otp, f"ids_table,hash={hashed_id}".encode())
        expire_time_encrypted = user_cipher.encrypt(new_ids_nonce, expire_time, f"ids_table,hash={hashed_id}".encode())

        cursor.execute("UPDATE Ids SET voted = (?), OTP = (?), expire_time = (?), nonce = (?) WHERE id_hash=(?)",
                        (voted_encrypted, otp_encrypted, expire_time_encrypted, new_ids_nonce, hashed_id,))
        conn.commit()

        # update that token has been used
        cursor.execute("UPDATE Tokens SET used = (?) WHERE token_hash=(?)", ('1', hashed_token,))
        conn.commit()
        conn.close()

        # redirect to final page
        return redirect(url_for("last_page"))
    
    # if we just got here from token screen
    else:  # GET request
        return render_template('vote.html', user_id=user_id)


@app.route('/last_page', methods=['GET'])
def last_page():
    # load last screen
    return render_template('last_screen.html')


def open_browser():
    # open the web page automatically
    webbrowser.open_new("http://127.0.0.1:5000/")


if __name__ == '__main__':
    load_dotenv()
    # open once upon call for main
    threading.Timer(1, open_browser).start()
    app.run(debug=False)
