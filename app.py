
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
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

#tells Python to open the hidden .env file and read it
load_dotenv()

app = Flask(__name__)

app.secret_key = 'super_secret_key'
CORS(app) #allows Chrome Extension to talk to local server


limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"] # Standard fallback limits
)

#database connection
def get_db_connection():
    return pymysql.connect(
        host="127.0.0.1", 
        user="root",
        password="bscvlad692004",
        database="password_db"
    )

def log_audit_event(user_id, website, username, action_type):
    db = get_db_connection()
    cursor = db.cursor()
    query = "INSERT INTO audit_logs (user_id, website, username, action_type) VALUES (%s, %s, %s, %s)"
    cursor.execute(query, (user_id, website, username, action_type))
    db.commit()
    db.close()

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

    #audit log for creation
    log_audit_event(user_id, website, username, "Created")

def get_vault_items():
    user_id = session.get('user_id')
    user_key = session.get('user_key')
    if not user_id or not user_key: return []

    db = get_db_connection()
    cursor = db.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT * FROM my_vault WHERE user_id = %s", (user_id,))
    items = cursor.fetchall()
    db.close()

    return items

    
def get_similar_password(new_password):
    user_key = session.get('user_key')
    if not user_key:
        return None

    items = get_vault_items()
    personal_cipher = Fernet(user_key.encode())

    for account in items:
        try:
            # Decrypt the stored password before comparing
            decrypted_pass = personal_cipher.decrypt(account['password'].encode()).decode()
        except Exception:
            continue  # skip items that can't be decrypted

        #similarity ratio: 0.0 (completely different) to 1.0 (identical)
        similarity = difflib.SequenceMatcher(None, new_password, decrypted_pass).ratio()

        if similarity >= 0.8:
            return account['website']
    return None  #Returns None if no similar passwords are found

#register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password') 

       
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))
            
        #hash the master password before saving
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

@app.route('/api/register/check', methods=['POST'])
@limiter.limit("10 per minute")  #rate limiting
def api_register_check():
    data = request.json
    new_password = data.get('password')
    
    if not new_password:
        return jsonify({"status": "empty"})

    stats = zxcvbn(new_password)
    
 
    is_leaked = check_leaked(new_password)
    
    if is_leaked:
        return jsonify({"status": "refused", "reason": "Refused: Found in a known data breach!"})
    elif stats['score'] < 3:
        return jsonify({"status": "refused", "reason": f"Too weak (Score: {stats['score']}/4). Takes {stats['guesses']} guesses to crack."})
    else:
        return jsonify({"status": "approved", "reason": f"Strong Password! (Score: {stats['score']}/4)"})
    

#key generator (PBKDF2 - 600,000 Iterations)
def generate_user_key(master_password, salt_string):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_string.encode('utf-8'), #using username as the salt
        iterations=600000,                #the 0.5 second delay!
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))

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
            session['user_key'] = generate_user_key(password,username).decode('utf-8')  
            
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

#change of master key
@app.route('/rotate_key', methods=['POST'])
@login_required
def rotate_key():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    user_id = session.get('user_id')
    username = session.get('username')
    
    db = get_db_connection()
    cursor = db.cursor(pymysql.cursors.DictCursor)
    
    try:
        #verify old password
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user or not check_password_hash(user['password_hash'], current_password):
            return jsonify({"success": False, "error": "Incorrect current Master Password."}), 403
            
        #generate old and new keys
        old_key = generate_user_key(current_password, username)
        new_key = generate_user_key(new_password, username)
        
        old_cipher = Fernet(old_key)
        new_cipher = Fernet(new_key)
        
        #fetch all of the user's locked vault items
        cursor.execute("SELECT id, password FROM my_vault WHERE user_id = %s", (user_id,))
        items = cursor.fetchall()
        
        #loop through and re-encrypt every password
        for item in items:
            #unlock with old key
            plain_text = old_cipher.decrypt(item['password'].encode()).decode()
            #lock with new key
            new_encrypted = new_cipher.encrypt(plain_text.encode()).decode()
            #overwrite in database
            cursor.execute("UPDATE my_vault SET password = %s WHERE id = %s", (new_encrypted, item['id']))
        
        #update the user's login hash in MariaDB
        new_hash = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user_id))
        
        db.commit()
        
        #update the active session key so the app doesn't break
        session['user_key'] = new_key.decode('utf-8')

        #audit log for master key rotation
        log_audit_event(user_id, "Secure Vault System", username, "Master Key Changed")
        
        return jsonify({"success": True, "message": "Master Password updated and vault completely re-encrypted!"})
        
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "error": f"Encryption error: {str(e)}"}), 500
    finally:
        db.close()

@app.route('/delete/<int:id>', methods=['POST'])
def delete_password(id):
    db = get_db_connection()
    cursor = db.cursor(pymysql.cursors.DictCursor)
    
    # NEW: Fetch the item details BEFORE deleting it so we can log it
    cursor.execute("SELECT website, username FROM my_vault WHERE id = %s", (id,))
    item = cursor.fetchone()
    
    if item:
        log_audit_event(session.get('user_id'), item['website'], item['username'], "Deleted")
    
    # Now delete it
    cursor.execute("DELETE FROM my_vault WHERE id = %s", (id,))
    db.commit()
    db.close()
    
    flash("Password deleted successfully!", "success")
    return redirect(url_for('home'))
#check if we have a password for the current website
@app.route('/api/get_credentials', methods=['POST'])
def api_get_credentials():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized!"})  
        
    data = request.json
    website_url = data.get('url') 
    master_password = data.get('master_password') # Grab the password from the extension
    
    items = get_vault_items() # Returns encrypted items
    username = session.get('username')
    
    for account in items:
        if website_url in account['website'] or account['website'] in website_url:
            #assume we will send a blank password for safety
            response_data = {
                "found": True,
                "username": account['username'],
                "password": "" 
            }
            
            #if the extension provided the Master Password, unlock it
            if master_password:
                try:
                    derived_key = generate_user_key(master_password, username)
                    personal_cipher = Fernet(derived_key)
                    #swap the blank string for the real, decrypted password
                    response_data['password'] = personal_cipher.decrypt(account['password'].encode()).decode()

                    log_audit_event(session['user_id'], account['website'], account['username'], "Extension Autofill")
                except Exception:
                    pass #if the password was wrong, leave it blank
                    
            return jsonify(response_data)
            
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
        session['user_key'] = generate_user_key(password,username).decode('utf-8')
        
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

#Stateless decryption endpoint
@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json()
    item_id = data.get('item_id')
    master_password = data.get('master_password')
    
    user_id = session.get('user_id')
    username = session.get('username')

    db = get_db_connection()
    cursor = db.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT website, username, password FROM my_vault WHERE id = %s AND user_id = %s", (item_id, user_id))
    item = cursor.fetchone()
    db.close()

    if not item:
        return jsonify({"success": False, "error": "Item not found"}), 404

    try:
        #make the key from the password the user just typed
        derived_key = generate_user_key(master_password, username)
        personal_cipher = Fernet(derived_key)
        
        #decrypt the password
        decrypted_password = personal_cipher.decrypt(item['password'].encode()).decode()
        
        log_audit_event(user_id, item['website'], item['username'], "Viewed on Dashboard")
        
        #send it back
        return jsonify({"success": True, "decrypted_password": decrypted_password})
        
    except Exception as e:
        print(f"Decryption Crash: {e}")
        return jsonify({"success": False, "error": "Invalid Master Password"}), 403



@app.route('/history')
@login_required
def history():
    user_id = session.get('user_id')
    
    db = get_db_connection()
    cursor = db.cursor(pymysql.cursors.DictCursor)
    
    # Fetch logs, ordered by newest first (DESC)
    cursor.execute("SELECT website, username, action_type, timestamp FROM audit_logs WHERE user_id = %s ORDER BY timestamp DESC", (user_id,))
    logs = cursor.fetchall()
    db.close()
    
    return render_template('history.html', logs=logs)



if __name__ == '__main__':
    app.run(debug=True)
