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

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.sqlite'
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
    __tablename__ = 'user'
    id = db.Column(db.Integer(), primary_key=True)

    login_name = db.Column(db.String(), unique=True, index=True)
    password = db.Column(db.String(128))
    name = db.Column(db.String())
    address = db.Column(db.Text())
    email = db.Column(db.String())
    role = db.Column(db.String())

    pools = db.relationship('Pool', backref='user', lazy='dynamic')
    shops = db.relationship('Shop', backref='user', lazy='dynamic')

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
    __tablename__ = 'user'
    __table_args__ = {'useexisting': True}

    def __init__(self, login_name, password):
        super().__init__(login_name, password)
        self.role = 'PoolOwner'


class PoolShopAdmin(User, db.Model):
    __tablename__ = 'user'
    __table_args__ = {'useexisting': True}

    def __init__(self, login_name, password):
        super().__init__(login_name, password)
        self.role = 'PoolShopAdmin'


class SPACSAdmin(User, db.Model):
    __tablename__ = 'user'
    __table_args__ = {'useexisting': True}

    def __init__(self, login_name, password):
        super().__init__(login_name, password)
        self.role = 'SPACSAdmin'


class Shop(db.Model):
    __tablename__ = 'shop'
    id = db.Column(db.Integer(), primary_key=True)

    shop_admin_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    pools = db.relationship('Pool', backref='shop', lazy='dynamic')

    def __init__(self, shop_admin):
        self.shop_admin_id = shop_admin


class Pool(db.Model):
    __tablename__ = 'pool'
    id = db.Column(db.Integer(), primary_key=True)

    length = db.Column(db.Float())
    width = db.Column(db.Float())
    depth = db.Column(db.Float())
    material = db.Column(db.String())
    pool_type = db.Column(db.String())

    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    shop_id = db.Column(db.Integer, db.ForeignKey('shop.id'))
    reports = db.relationship('Report', backref='pool', lazy='dynamic')

    def __init__(self, length, width, depth,
                 material, pool_type, owner, shop_id):
        self.length = length
        self.width = width
        self.depth = depth
        self.material = material
        self.pool_type = pool_type
        self.owner_id = owner
        self.shop_id = shop_id


class Report(db.Model):
    __tablename__ = 'report'
    id = db.Column(db.Integer(), primary_key=True)

    report = db.Column(db.Text())
    date = db.Column(db.String())

    pool_id = db.Column(db.Integer, db.ForeignKey('pool.id'))

    def __init__(self, report, date):
        self.report = report
        self.date = date


class LoginForm(Form):
    login_name = StringField('Login name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class NewPoolForm(Form):
    length = StringField('Length', validators=[DataRequired()])
    width = StringField('Width', validators=[DataRequired()])
    depth = StringField('Depth', validators=[DataRequired()])
    material = StringField('Pool Material', validators=[DataRequired()])
    pool_type = StringField('Pool Type', validators=[DataRequired()])


class NewPoolShop(Form):
    pass


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(login_name=form.login_name.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(request.args.get('next') or url_for('pools'))
        else:
            flash('Login failed.', 'danger')
    return render_template('login.html', form=form)


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