
from flask import Flask, render_template, request, redirect, url_for, session, flash
from zxcvbn import zxcvbn
import pymysql
import difflib  #compare strings
from flask import jsonify 
from flask_cors import CORS #to run: pip install flask-cors
from cryptography.fernet import Fernet
import hashlib
import requests
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
#import hashlib
import base64

#tells Python to open the hidden .env file and read it
load_dotenv()

app = Flask(__name__)

app.secret_key = 'super_secret_key'
CORS(app) #allows Chrome Extension to talk to local server

#database connection
def get_db_connection():
    return pymysql.connect(
        host="127.0.0.1", 
        user="root",
        password="bscvlad692004",
        database="password_db"
    )

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access your vault.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_leaked_local(password):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM leaked_passwords WHERE password = %s", (password,))
    match = cursor.fetchone()
    db.close()
    return bool(match)


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
    user_id = session.get('user_id')
    user_key = session.get('user_key') # Get user's personal key
    if not user_id or not user_key: return 

    #create a personal encryptor just for them
    personal_cipher = Fernet(user_key.encode())
    encrypted_password = personal_cipher.encrypt(password.encode()).decode()

    db = get_db_connection()
    cursor = db.cursor()
    query = "INSERT INTO my_vault (user_id, website, username, password) VALUES (%s, %s, %s, %s)"
    cursor.execute(query, (user_id, website, username, encrypted_password))
    db.commit()
    db.close()

def get_vault_items():
    user_id = session.get('user_id')
    user_key = session.get('user_key')
    if not user_id or not user_key: return []

    personal_cipher = Fernet(user_key.encode())

    db = get_db_connection()
    cursor = db.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT * FROM my_vault WHERE user_id = %s", (user_id,))
    items = cursor.fetchall()
    db.close()

    #decrypt everything using user's key
    for item in items:
        try:
            item['password'] = personal_cipher.decrypt(item['password'].encode()).decode()
        except Exception:
            item['password'] = "ERROR: Old Key"

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

#register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hash the master password before saving!
        hashed_pw = generate_password_hash(password)
        
        db = get_db_connection()
        cursor = db.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed_pw))
            db.commit()
            flash("Account created! You can now log in.", "success")
            return redirect(url_for('login'))
        except pymysql.err.IntegrityError:
            flash("Username already exists!", "danger")
        finally:
            db.close()
            
    return render_template('register.html')

# The Magic Key Generator
def generate_user_key(master_password):
    # turn user password into a 32-byte Fernet encryption key
    key = hashlib.sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(key)

#login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember') 
        db = get_db_connection()
        cursor = db.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        db.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            
            # ZERO KNOWLEDGE:save the user's personal key in the session!
            session['user_key'] = generate_user_key(password).decode('utf-8')
            
            # remember me logic
            if remember:
                session.permanent = True # Cookie lasts for a month
            else:
                session.permanent = False # Cookie dies when browser closes
                
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password.", "danger")
            
    return render_template('login.html')

#logout
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))


#home page
@app.route('/', methods=['GET', 'POST'])
@login_required
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
        is_leaked_local=check_leaked_local(password)
        similar_to_website = get_similar_password(password)
        
        
        if is_leaked or is_leaked_local:
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
    
    return render_template('index.html', saved_accounts=saved_accounts)

#delete a password
@app.route('/delete/<int:id>', methods=['POST'])
def delete_password(id):
    db = get_db_connection()
    cursor = db.cursor()
    
    cursor.execute("DELETE FROM my_vault WHERE id = %s", (id,))
    
    db.commit()
    db.close()
    
    flash(" Password deleted successfully!", "success")
    return redirect(url_for('home'))

#check if we have a password for the current website
@app.route('/api/get_credentials', methods=['POST'])
def api_get_credentials():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized!"})  
        
    data = request.json
    website_url = data.get('url') 
    
    items = get_vault_items() #return decrypted passwords
    
    for account in items:
        if website_url in account['website'] or account['website'] in website_url:
            return jsonify({
                "found": True,
                "username": account['username'],
                "password": account['password'] 
            })
            
    return jsonify({"found": False})

#check a new password against my security rules
@app.route('/api/password/check', methods=['POST'])
def api_check_security():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized!"}) 
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

#save a new secure password to the vault directly from the extension
@app.route('/api/save_credentials', methods=['POST'])
def api_save_credentials():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized!"}) 
    data = request.json
    website = data.get('url')
    username = data.get('username')
    password = data.get('password')
    
    save_to_vault(website, username, password)
    
    return jsonify({"status": "success", "message": "Saved to vault!"})

# Lets the extension log in
@app.route('/api/login', methods=['POST'])
def api_extension_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    db = get_db_connection()
    cursor = db.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    db.close()
    
    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        
        #Give the extension the personal key too
        session['user_key'] = generate_user_key(password).decode('utf-8')
        
        #Extensions should usually act as "Remember Me" automatically
        session.permanent = True 
        
        return jsonify({"status": "success", "message": "Logged in!"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"})


# Health-Check endpoint updated to check for sessions
@app.route('/info', methods=['GET'])
def api_info():
    if 'user_id' in session:
        return jsonify({"status": "logged_in", "username": session['username']})
    else:
        return jsonify({"status": "logged_out"})

if __name__ == '__main__':
    app.run(debug=True)
