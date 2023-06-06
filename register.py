import bcrypt
import datetime
import re
import uuid
from flask import jsonify, request
from flask_mail import Message
from pymongo import MongoClient

from app import app, limiter, mail, users

@app.route('/register', methods=['POST'])
@limiter.limit("5/minute")
def register():
    name = request.json['name']
    email = request.json['email']
    password = request.json['password']

    name = name.strip()
    email = email.strip()

    if not validate_email(email):
        return jsonify({'message': 'Invalid email format'}), 400

    if users.find_one({'email': email}):
        return jsonify({'message': 'Email already exists'}), 400

    password_errors = validate_password(password)
    if password_errors:
        return jsonify({'message': 'Password does not meet the criteria', 'errors': password_errors}), 400

    user_id = str(uuid.uuid4())[:10]
    current_datetime = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
    verification_token = generate_verification_token()

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    user_data = {
        'user_id': user_id,
        'name': name,
        'email': email,
        'password': hashed_password,
        'salt': salt,
        'created_at': current_datetime,
        'status': 'inactive',
        'verification_token': verification_token
    }
    users.insert_one(user_data)

    send_verification_email(email, verification_token)

    return jsonify({'message': 'Registration successful. Please check your email for verification.'}), 200

@app.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    user = users.find_one({'verification_token': token})

    if not user:
        return jsonify({'message': 'Invalid verification token'}), 400

    users.update_one({'_id': user['_id']}, {'$set': {'status': 'active'}})

    return jsonify({'message': 'Email verification successful'}), 200

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(pattern, email):
        return False
    return True

def validate_password(password):
    errors = []
    if len(password) < 8:
        errors.append('Password should be at least 8 characters long')
    if not any(char.isupper() for char in password):
        errors.append('Password should contain at least one uppercase letter')
    if not any(char.islower() for char in password):
        errors.append('Password should contain at least one lowercase letter')
    if not any(char.isdigit() for char in password):
        errors.append('Password should contain at least one numeric digit')
    return errors

def generate_verification_token():
    return str(uuid.uuid4())

def send_verification_email(email, token):
    msg = Message('Email Verification', sender='no-reply@vvfin.in', recipients=[email])
    msg.body = f'Please click the following link to verify your email: http://34.227.117.43/verify/{token}'
    mail.send(msg)
