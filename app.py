from flask import Flask
from flask_mail import Mail
from pymongo import MongoClient
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager

app = Flask(__name__)

@app.route('/')
def main_func():
    return "Welcome to API Server"

# MongoDB Configuration
client = MongoClient('mongodb+srv://admin:pawan2244@cluster0.mv4ja.mongodb.net/SmartAPI?retryWrites=true&w=majority')
db = client['SmartAPI']
users = db['users']

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtppro.zoho.in'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'no-reply@vvfin.in'
app.config['MAIL_PASSWORD'] = 'y5KYGGFvjYTx'

mail = Mail(app)

# Flask-Limiter Configuration
limiter = Limiter(app)
limiter.key_func = get_remote_address

# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
jwt = JWTManager(app)

# Importing the register and login components
from components.register import *
from components.login import *

if __name__ == '__main__':
    app.run(debug=True, port=8000, host='0.0.0.0')
