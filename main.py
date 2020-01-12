from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
from flask_mysqldb import MySQL
import jwt
import datetime
import MySQLdb.cursors
import re
import hashlib
import os
import constant

app = Flask(__name__)

# Set secret key for session (best to be randomly generated for the sake of security)
app.secret_key = 'd2da6c79cb2e23287aa66d85dedf13ab3b0c72a72497d4e7d1ca0f65d9a48584'

# Set details of database connection
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '#Andromorf97$!'
app.config['MYSQL_DB'] = 'login_db'

# ... and initialize!
mysql = MySQL(app)

app.config['SECRET_KEY'] = 'd2da6c79cb2e23287aa66d85dedf13ab3b0c72a72497d4e7d1ca0f65d9a48584'

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True

def hash_password(password):
    salt=os.urandom(constant.SALT_LEN)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, constant.SHA256_ITER_NUM)
    hashed_password = salt + key
    return hashed_password.hex()

def get_salt_and_key_back(hashed_password):
    hashed_password = bytes.fromhex(hashed_password)
    salt = hashed_password[:constant.SALT_LEN]
    key = hashed_password[constant.SALT_LEN:]
    return salt, key

def verify_password(hashed_password, password_to_verify):
    salt, key = get_salt_and_key_back(hashed_password)
    new_key = hashlib.pbkdf2_hmac('sha256', password_to_verify.encode('utf-8'), salt, 1000000)
    return new_key == key

def find_user_by_username(username):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE username=%s', (username,))
    user = cursor.fetchone()
    return user

def add_new_user(username, password):
    hashed_password = hash_password(password)
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('INSERT INTO users(username, hashed_password) VALUES (%s, %s)', (username, hashed_password))
    mysql.connection.commit()
    
def encode_access_token(username):
    payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=10),
            'iat': datetime.datetime.utcnow(),
            'sub': username
        }
    return jwt.encode(
            payload,
            key=app.config.get('SECRET_KEY'),
            algorithm='HS256'
        )
    
def decode_access_token(access_token):
    payload = jwt.decode(access_token, key=app.config.get('SECRET_KEY'))
    return payload['sub']

@app.route('/FlaskApp/', methods=['GET','POST'])
def login():
    # Output message
    if 'msg' in session:
        msg = session['msg']
    else:
        msg = ''
    # If fields in form are filled in...
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        
        user = find_user_by_username(username)
        
        # ... and if typed username match an existing user...
        if user:
            # ... then if typed password is OK...
            if verify_password(user['hashed_password'], password):
                # ... we can log in user succesfully and generate access token for him 
                access_token = encode_access_token(username)
                session['access_token'] = access_token
                return redirect(url_for('home'))
         # In other case user does not exist or used credentials are not valid:
        msg = 'Incorrect username or password!'
    
    # Show login form with message (if any)
    return render_template('index.html', msg=msg)

@app.route('/FlaskApp/register', methods=['GET','POST'])
def register():
    # Output message
    msg = ''
    # If fields in form are filled in...
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        
        user = find_user_by_username(username)
        # ... and if something is wrong with typed data, then print relevant error message
        if user:
            msg = 'Entered username already exists!'
        elif not username or not password:
            msg = 'Please fill in the form!'
        elif not re.match(r'^\w+$', username):
            msg = 'Username must be alphanumeric!'
        # In other case it is possible to add new user
        else:
            add_new_user(username, password)
            msg = 'You have succesfully registered!'
    elif request.method == 'POST':
        msg = 'Please fill in the form!'
    # Show register form with message (if any)
    return render_template('register.html', msg=msg)

@app.route('/FlaskApp/home')
def home():
    access_token = session['access_token']
    try:
        username = decode_access_token(access_token)
    except jwt.ExpiredSignatureError:
        session['msg'] = 'Your session has expired, please log in again!'
        return redirect(url_for('login'))
    except jwt.InvalidTokenError:
        session['msg'] = 'Something is wrong with your session, please log in again!'
        return redirect(url_for('login'))
    return render_template('home.html', username=username)                

if __name__ == '__main__':
    app.run(ssl_context='adhoc')


