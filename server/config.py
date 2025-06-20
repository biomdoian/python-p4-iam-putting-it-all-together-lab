from flask import Flask
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from flask_cors import CORS # Assuming CORS might be used

app = Flask(__name__)
# IMPORTANT: Replace this with a real secret key from os.urandom(16) in a real application!
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False # For pretty-printing JSON responses

# This naming convention for foreign keys is crucial to avoid 'KeyError: column_names'
metadata = MetaData(naming_convention={
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
})
db = SQLAlchemy(metadata=metadata) # Initialize db with the metadata

migrate = Migrate(app, db) # Initialize Migrate with the app and db
db.init_app(app) # Bind db to the app instance

bcrypt = Bcrypt(app) # Initialize Bcrypt with the app instance
api = Api(app) # Initialize Flask-RESTful Api with your Flask app

CORS(app, supports_credentials=True) # Enable CORS with credentials support for session cookies

