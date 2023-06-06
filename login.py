import bcrypt
import html
import datetime
import pytz
import geocoder
from flask import jsonify, request
from pymongo import MongoClient
from flask_mail import Message
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
    get_jwt,
    JWTManager,
)
import re

from app import app, limiter, users, mail, jwt

MAX_LOGIN_ATTEMPTS = 3
BLOCK_DURATION_HOURS = 24
TOKEN_EXPIRATION = datetime.timedelta(days=1)

client = MongoClient('mongodb+srv://admin:pawan2244@cluster0.mv4ja.mongodb.net/?retryWrites=true&w=majority')
db = client['PubKeys']
tokens_collection = db['tokens']
blacklisted_tokens = db['blacklisted_tokens']
logs_collection = db['logs']

@app.route('/login', methods=['POST'])
@limiter.limit("5/minute")
def login():
    email = request.json['email']
    password = request.json['password']

    # Clean and validate email
    email = html.escape(email.strip())
    if not validate_email(email):
        return jsonify({'message': 'Invalid email format'}), 400

    # Retrieve user from database
    user = users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'Invalid email or password'}), 400

    # Check if account is blocked
    if is_account_blocked(user):
        send_account_block_alert(user['email'])
        return jsonify({'message': 'Account blocked. Please try again after 24 hours.'}), 403

    # Validate password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        increment_failed_login_attempts(user)
        return jsonify({'message': 'Invalid email or password'}), 400

    # Reset failed login attempts
    reset_failed_login_attempts(user)

    # Generate access and refresh tokens
    access_token = create_access_token(identity=str(user['_id']), expires_delta=TOKEN_EXPIRATION, fresh=True)
    refresh_token = create_refresh_token(identity=str(user['_id']), expires_delta=TOKEN_EXPIRATION)
    store_tokens(user['_id'], access_token, refresh_token)

    # Log successful login
    log_login_attempt(user['_id'], request.remote_addr)

    # Update last login
    update_last_login(user['_id'])

    # Send login alert to user
    send_login_alert(user['email'], request.remote_addr)

    return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200

def is_account_blocked(user):
    return user.get('block_expiration') and user['block_expiration'] > datetime.datetime.now(pytz.timezone('Asia/Kolkata'))

def send_account_block_alert(email):
    msg = Message('Account Blocked', sender='no-reply@vvfin.in', recipients=[email])
    msg.body = 'Your account has been blocked due to multiple failed login attempts. Please try again after 24 hours.'
    mail.send(msg)

def increment_failed_login_attempts(user):
    attempts = user.get('failed_login_attempts', 0) + 1
    if attempts >= MAX_LOGIN_ATTEMPTS:
        block_expiration = datetime.datetime.now(pytz.timezone('Asia/Kolkata')) + datetime.timedelta(hours=BLOCK_DURATION_HOURS)
        users.update_one({'_id': user['_id']}, {'$set': {'failed_login_attempts': attempts, 'block_expiration': block_expiration}})
    else:
        users.update_one({'_id': user['_id']}, {'$set': {'failed_login_attempts': attempts}})

def reset_failed_login_attempts(user):
    users.update_one({'_id': user['_id']}, {'$unset': {'failed_login_attempts': 1, 'block_expiration': 1}})

def store_tokens(user_id, access_token, refresh_token):
    tokens_collection.insert_one({'user_id': user_id, 'access_token': access_token, 'refresh_token': refresh_token})

def log_login_attempt(user_id, ip_address):
    location_data = get_location(ip_address)
    browser = get_browser(request.user_agent.string)
    logs_collection.insert_one({'user_id': user_id, 'ip_address': ip_address, 'location': location_data, 'browser': browser, 'timestamp': datetime.datetime.now(pytz.timezone('Asia/Kolkata'))})

def get_location(ip_address):
    g = geocoder.ip(ip_address)
    return {'country': g.country, 'city': g.city}

def get_browser(user_agent):
    if "chrome" in user_agent.lower():
        return "Chrome"
    elif "firefox" in user_agent.lower():
        return "Firefox"
    elif "safari" in user_agent.lower():
        return "Safari"
    elif "edge" in user_agent.lower():
        return "Edge"
    elif "opera" in user_agent.lower():
        return "Opera"
    else:
        return "Unknown"

def update_last_login(user_id):
    users.update_one({'_id': user_id}, {'$set': {'last_login': datetime.datetime.now(pytz.timezone('Asia/Kolkata'))}})

def send_login_alert(email, ip_address):
    location_data = get_location(ip_address)
    browser = get_browser(request.user_agent.string)
    msg = Message('Successful Login', sender='no-reply@vvfin.in', recipients=[email])
    msg.body = f'Your account was successfully logged in.\n\nIP Address: {ip_address}\nLocation: {location_data}\nBrowser: {browser}\nTimestamp: {datetime.datetime.now(pytz.timezone("Asia/Kolkata"))}'
    mail.send(msg)

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(pattern, email):
        return False
    return True

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_data):
    jti = jwt_data['jti']
    revoked_token = blacklisted_tokens.find_one({'jti': jti})
    if revoked_token:
        return jsonify({'message': 'The access token has been revoked.'}), 401
    else:
        return jsonify({'message': 'Invalid token.'}), 401


@jwt.token_in_blocklist_loader
def is_token_revoked(jwt_header, jwt_data):
    jti = jwt_data['jti']
    revoked_token = blacklisted_tokens.find_one({'jti': jti})
    return revoked_token is not None

@app.route('/refresh-token', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user, expires_delta=TOKEN_EXPIRATION, fresh=False)
    return jsonify({'access_token': access_token}), 200

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    blacklisted_tokens.insert_one({'jti': jti})
    return jsonify({'message': 'Successfully logged out'}), 200

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected_route():
    current_user = get_jwt_identity()
    return jsonify({'message': f'Protected route accessed by user: {current_user}'}), 200

@jwt.unauthorized_loader
def unauthorized_callback(error_string):
    return jsonify({'message': 'Unauthorized access', 'error': error_string}), 401

@app.route('/revoke-token', methods=['POST'])
@jwt_required()
def revoke_token():
    jti = get_jwt()['jti']
    blacklisted_tokens.insert_one({'jti': jti})
    return jsonify({'message': 'Token revoked'}), 200

@app.route('/protected-fresh', methods=['GET'])
@jwt_required(fresh=True)
def protected_fresh_route():
    current_user = get_jwt_identity()
    return jsonify({'message': f'Protected route (fresh token) accessed by user: {current_user}'}), 200




if __name__ == '__main__':
    app.run(debug=True)
