__author__ = 'Liam'

from flask import Flask, render_template
from flask_bootstrap import Bootstrap
app = Flask(__name__)
Bootstrap(app)

from datetime import datetime
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import UserMixin, AnonymousUserMixin
from flask.ext.bcrypt import Bcrypt

db = SQLAlchemy()
flask_bcrypt = Bcrypt()


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    login_name = db.Column(db.String(), unique=True, index=True)
    password = db.Column(db.String(128))
    user_type = db.relationship('Type', backref='user', lazy='dynamic')

    name = db.Column(db.String())
    address = db.Column(db.Text())
    email = db.Column(db.String())

    def __init__(self, email, password):
        self.password_hash = flask_bcrypt.generate_password_hash(password)
        self.email = email

    def check_password(self, value):
        return flask_bcrypt.check_password_hash(self.password_hash, value)

    def is_authenticated(self):
        if isinstance(self, AnonymousUserMixin):
            return False
        else:
            return True

    def is_active(self):
        return True

    def is_anonymous(self):
        if isinstance(self, AnonymousUserMixin):
            return True
        else:
            return False

    def get_id(self):
        return self.id

    def __repr__(self):
        return '<User %r>' % self.username


class Pool(db.Model):
    __tablename__ = 'pools'
    id = db.Column(db.Integer(), primary_key=True)
    ph = db.Column(db.Float())
    ORP = db.Column(db.Float())
    TA = db.Column(db.Float())
    temp = db.Column(db.Float())
    water_hardness = db.Column(db.Float())
    last_filter_operation = db.Column(db.DateTime())
    water_flow_rate = db.Column(db.Float())
    chlorinator_status = db.Column(db.String())
    water_level_status = db.Column(db.String())


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)