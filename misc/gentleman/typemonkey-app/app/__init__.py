from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_bootstrap import Bootstrap5
from config import FlaskConfig

app = Flask(__name__)
app.config.from_object(FlaskConfig)
bootstrap = Bootstrap5(app)
db = SQLAlchemy(app)
crypt = Bcrypt(app)
login = LoginManager(app)
login.login_view = 'login'
with app.app_context():
    from app.models import User
    db.create_all()

from app import routes