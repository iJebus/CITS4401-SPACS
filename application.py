"""Main application runtime for the CITS4401 SPACS Assignment.
"""

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import UserMixin, \
    AnonymousUserMixin, LoginManager, login_user, login_required, logout_user
from flask.ext.bcrypt import Bcrypt
from flask_wtf import Form
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
# from wtforms import ValidationError


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'CHEESE'

Bootstrap(app)
db = SQLAlchemy(app)
flask_bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin, AnonymousUserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    login_name = db.Column(db.String(), unique=True, index=True)
    password = db.Column(db.String(128))
    name = db.Column(db.String())
    address = db.Column(db.Text())
    email = db.Column(db.String())
    role = db.Column(db.String())

    def __init__(self, login_name, password):
        self.login_name = login_name
        self.password = flask_bcrypt.generate_password_hash(password)

    def __repr__(self):
        return "<{}, {}>".format(self.login_name, self.role)

    def is_administrator(self):
        return self.role == 'SPACSAdmin'

    def check_password(self, value):
        return flask_bcrypt.check_password_hash(self.password, value)


class PoolOwner(User, db.Model):
    __tablename__ = 'users'
    __table_args__ = {'useexisting': True}

    def __init__(self, login_name, password):
        super().__init__(login_name, password)
        self.role = 'PoolOwner'


class PoolShopAdmin(User, db.Model):
    __tablename__ = 'users'
    __table_args__ = {'useexisting': True}

    def __init__(self, login_name, password):
        super().__init__(login_name, password)
        self.role = 'PoolShopAdmin'


class SPACSAdmin(User, db.Model):
    __tablename__ = 'users'
    __table_args__ = {'useexisting': True}

    def __init__(self, login_name, password):
        super().__init__(login_name, password)
        self.role = 'SPACSAdmin'


"""class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    login_name = db.Column(db.String(), unique=True, index=True)
    password = db.Column(db.String(128))

    name = db.Column(db.String())
    address = db.Column(db.Text())
    email = db.Column(db.String())

    discriminator = db.Column(db.String())
    __mapper_args__ = {'polymorphic_on': discriminator}

    def __init__(self, login_name, password):
        self.login_name = login_name
        self.password = flask_bcrypt.generate_password_hash(password)

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



    def __repr__(self):
        return '<User {}, type {}>'.format(self.username, self.discriminator)"""


class LoginForm(Form):
    login_name = StringField('Login name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class Pool(db.Model):
    __tablename__ = 'pools'
    id = db.Column(db.Integer(), primary_key=True)
    ph = db.Column(db.Float())
    orp = db.Column(db.Float())
    ta = db.Column(db.Float())
    temp = db.Column(db.Float())
    water_hardness = db.Column(db.Float())
    last_filter_operation = db.Column(db.DateTime())
    water_flow_rate = db.Column(db.Float())
    chlorinator_status = db.Column(db.String())
    water_level_status = db.Column(db.String())

    # users = db.relationship('User', backref='pool', lazy='dynamic')

    """owner_id =
    shop_administrator_id =
    spacs_administrator_id ="""


@app.route('/', methods=["GET", "POST"])
def index():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(login_name=form.login_name.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(request.args.get('next') or url_for('pools'))
        else:
            flash('Login failed.', 'danger')
    return render_template('index.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/pools')
@login_required
def pools():
    return render_template('pools.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)