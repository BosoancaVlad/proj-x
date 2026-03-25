
from flask import Flask, render_template, request, redirect, url_for, session, flash
from zxcvbn import zxcvbn
import pymysql
import difflib  #compare strings!
from flask import jsonify 
from flask_cors import CORS #to run: pip install flask-cors
from cryptography.fernet import Fernet
import hashlib
import requests
import os
from dotenv import load_dotenv

# 1. This tells Python to open the hidden .env file and read it
load_dotenv()

MASTER_KEY = os.getenv("MASTER_KEY").encode('utf-8')

app = Flask(__name__)

cipher_suite = Fernet(MASTER_KEY)


app.secret_key = 'super_secret_key'
CORS(app) #allows Chrome Extension to talk to local server

#database connection
def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        port=int(os.getenv("DB_PORT")), # Remember, ports must be integers
        database=os.getenv("DB_NAME")
    )

def check_leaked(password):
    #scramble user's password using SHA-1 math(gibberish)
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    #first 5 characters, and the rest
    first_5 = sha1_password[:5]
    the_rest = sha1_password[5:]
    
    #send ONLY the first 5 characters to HIBP server
    url = f"https://api.pwnedpasswords.com/range/{first_5}"
    
    try:
        response = requests.get(url)
        
        #Check if rest of the gibberish is inside the leaked list
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == the_rest:
                    return True 
        return False 
        
    except Exception as e:
        print(f"API Error: {e}")
        return False #if the API crashes/no internet, let the user proceed

def save_to_vault(website, username, password):
    db = get_db_connection()
    cursor = db.cursor()

    #encrypt the password
    encrypted_password = cipher_suite.encrypt(password.encode()).decode()

    query = "INSERT INTO my_vault (website, username, password) VALUES (%s, %s, %s)"
    cursor.execute(query, (website, username, encrypted_password))
    
    db.commit()
    db.close()

def get_vault_items():
    db = get_db_connection()
    cursor = db.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT * FROM my_vault")
    items = cursor.fetchall()
    db.close()
    return items

    
def get_similar_password(new_password):
    items = get_vault_items()
    for account in items:
        saved_pass = account['password']
        #similarity ratio: 0.0 (completely different) to 1.0 (identical)
        similarity = difflib.SequenceMatcher(None, new_password, saved_pass).ratio()
        
        if similarity >= 0.8:
            return account['website']
    return None  #Returns None if no similar passwords are found

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']

        clean_url = website
        if not clean_url.startswith(('http://', 'https://')):
            clean_url = f'http://{clean_url}'
        
        #calculate stats
        stats = zxcvbn(password)
        is_leaked = check_leaked(password)
        similar_to_website = get_similar_password(password)
        
        
        if is_leaked:
            flash(f"<strong>REFUSED!</strong> This password was found in leaked password lists. Change it now for <a href='{clean_url}' target='_blank' style='color: #721c24; text-decoration: underline;'>{website}</a>.", "danger")
            
        elif stats['score'] < 3:
            flash(f"<strong>REFUSED!</strong> Password is too weak (Score: {stats['score']}/4). It can be cracked in just {stats['guesses']:,} guesses. Please use a stronger password for <a href='{clean_url}' target='_blank' style='color: #721c24; text-decoration: underline;'>{website}</a>.", "danger")
            
        elif similar_to_website:
            flash(f"<strong>REFUSED!</strong> This password is too similar to the one you already use for <strong>{similar_to_website}</strong>. Password reuse is a major security risk. Please generate a unique password.", "danger")
       
        else:
            save_to_vault(website, username, password)
            flash(f"<strong>Password is safe!</strong> (Score: {stats['score']}/4). It would take a hacker roughly {stats['guesses']:,} guesses to crack it. Saved to your vault for <a href='{clean_url}' target='_blank' style='color: #155724; text-decoration: underline;'>{website}</a>.", "success")
            
        return redirect(url_for('home'))
    saved_accounts = get_vault_items()

    for account in saved_accounts:
        try:
            account['password'] = cipher_suite.decrypt(account['password'].encode()).decode()
        except Exception as e:
            pass # If it's an old, unencrypted password we don't consider it
    
    return render_template('index.html', saved_accounts=saved_accounts)

@app.route('/delete/<int:id>', methods=['POST'])
def delete_password(id):
    db = get_db_connection()
    cursor = db.cursor()
    
    cursor.execute("DELETE FROM my_vault WHERE id = %s", (id,))
    
    db.commit()
    db.close()
    
    flash("🗑️ Password deleted successfully!", "success")
    return redirect(url_for('home'))

#API 1: check if we have a password for the current website
@app.route('/api/get_credentials', methods=['POST'])
def api_get_credentials():
    data = request.json
    website_url = data.get('url') 
    
    items = get_vault_items()
    for account in items:
        if website_url in account['website'] or account['website'] in website_url:
            
            #Safety Net
            try:
                decrypted_password = cipher_suite.decrypt(account['password'].encode()).decode()
            except Exception:
                # If it crashes, it means this is an old password from yesterday. Just use it as-is!
                decrypted_password = account['password'] 
            
            return jsonify({
                "found": True,
                "username": account['username'],
                "password": decrypted_password
            })
            
    return jsonify({"found": False})

#API 2: check a new password against my security rules
@app.route('/api/password/check', methods=['POST'])
def api_check_security():
    data = request.json
    new_password = data.get('password')
    website = data.get('url')
    
    stats = zxcvbn(new_password)
    is_leaked = check_leaked(new_password)
    similar_to = get_similar_password(new_password)
    
    if is_leaked:
        return jsonify({"status": "refused", "reason": "Leaked in a data breach!"})
    elif similar_to:
        return jsonify({"status": "refused", "reason": f"Too similar to your {similar_to} password!"})
    elif stats['score'] < 3:
        return jsonify({"status": "refused", "reason": f"Too weak! Can be cracked in {stats['guesses']} guesses."})
    else:
        return jsonify({"status": "approved", "reason": "Password is secure."})

#API 3: save a new secure password to the vault directly from the extension
@app.route('/api/save_credentials', methods=['POST'])
def api_save_credentials():
    data = request.json
    website = data.get('url')
    username = data.get('username')
    password = data.get('password')
    
    save_to_vault(website, username, password)
    
    return jsonify({"status": "success", "message": "Saved to vault!"})

# Health-Check endpoint
@app.route('/info', methods=['GET'])
def api_info():
    #a simple hello message
    return jsonify({"message": "hello"})

if __name__ == '__main__':
    app.run(debug=True)
