import sqlite3
import webbrowser
import threading
from flask import Flask, render_template, request, redirect, url_for, jsonify
import hashlib
import time
import hmac
import secrets
from constants import INTERVAL_SIZE, HASH_ID_SERVER_KEY, HASH_CANDIDATE_SERVER_KEY

app = Flask(__name__)
DB_FILE = 'database.db'


# TODO: need to decrypt retrieved rows and encrypt them back (besides hash value of id)

@app.route('/')
def index():
    # log in screen
    return render_template('welcome_screen.html')


@app.route('/generate_otp', methods=['POST'])
def generate_otp():
    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400
    
    # connect and load db
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # search if id exists (based on hash)
    hashed_id = hmac.new(HASH_ID_SERVER_KEY, user_id.encode(), hashlib.sha256).hexdigest()
    
    # update if not present
    cursor.execute("SELECT * FROM Ids WHERE id_hash=(?)", (hashed_id,))
    Otp_row = cursor.fetchall()

    # if row does not exist in table
    if len(Otp_row) == 0:
        return "Invalid id"
    
    # check if user already voted - no OTP generation
    voted = Otp_row[0][1]
    if voted == '1':
        return "User already voted!"
        
    # generate otp
    expire_time = int(time.time()) + INTERVAL_SIZE  # valid for 30s
    otp = str(secrets.randbelow(10**10)).zfill(10)  # 10-digit random OTP

    # update otp and expire time
    # TODO: encrypt new values
    cursor.execute("UPDATE Ids SET otp = (?), expire_time = (?) WHERE id_hash = (?)",
                    (otp, expire_time, hashed_id,))
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

    # search if id exists (based on hash)
    hashed_id = hmac.new(HASH_ID_SERVER_KEY, user_id.encode(), hashlib.sha256).hexdigest()
    cursor.execute("SELECT * FROM Ids WHERE id_hash=(?)", (hashed_id,))
    ids_rows = cursor.fetchall()

    if len(ids_rows) == 0:
        return "Invalid id"

    # retieve otp information
    # TODO: decrypt
    _, _, otp, expire_time = ids_rows[0]

    # get cur time stamp
    current_time = int(time.time())

    # compare otps and make sure interval has not passed yet
    if current_time >= expire_time or user_otp != otp:
        return "Invalid OTP"

    # TODO: decrypt this value
    did_vote = ids_rows[0][1]
        
    # if voter have not voted yet, procceed
    if did_vote == '0':
        conn.close()
        return redirect(url_for('vote', user_id=user_id))
    else:
        return "You have already voted!"


@app.route('/vote/<user_id>', methods=['GET', 'POST'])
def vote(user_id):
    # connect and load db
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # if we post data
    if request.method == "POST":
        # check if user already voted - tried going back in the browser
        hashed_id = hmac.new(HASH_ID_SERVER_KEY, user_id.encode(), hashlib.sha256).hexdigest()
        cursor.execute("SELECT voted FROM Ids WHERE id_hash=(?)", (hashed_id,))
        row = cursor.fetchone()
        
        # TODO: decrypt
        did_vote = row[0]

        if did_vote == '1':
            return "User already voted!"
        
        # retrieve user choice
        candidate_name = request.form['option']

        # find candidate information
        candidate_hash = hmac.new(HASH_CANDIDATE_SERVER_KEY, candidate_name.encode(), hashlib.sha256).hexdigest()
        cursor.execute("SELECT * FROM Candidates WHERE candidate_hash=(?)", (candidate_hash,))
        candidate_rows = cursor.fetchall()

        # TODO: decrypt this value
        candidate_votes = candidate_rows[0][1]
        cursor.execute("UPDATE Candidates SET votes = (?) WHERE candidate_hash=(?)", (candidate_votes+1, candidate_hash,))
        # TODO: encrypt
        conn.commit()

        # update that voter has voted
        cursor.execute("UPDATE Ids SET voted = (?) WHERE id_hash=(?)", (1, hashed_id,))
        # TODO: encrypt
        conn.commit()
        conn.close()

        # redirect to final page
        return redirect(url_for("last_page"))
    
    # if we just got here from welcome screen
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
    # open once upon call for main
    threading.Timer(1, open_browser).start()
    app.run(debug=False)
