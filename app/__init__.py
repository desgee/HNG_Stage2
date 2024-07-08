from flask import Flask
import os
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager
from app.auth import auth


#initialize flask app
app = Flask(__name__)
 # Configuration
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres.sucilzhqzugjcucykwmo:rT12dIOsWoqV2wln@aws-0-eu-central-1.pooler.supabase.com:6543/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'



#instance of the db
db = SQLAlchemy(app)
jwt = JWTManager(app) 







from app import routes