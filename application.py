"""Main application runtime for the CITS4401 SPACS Assignment.
"""

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import UserMixin, AnonymousUserMixin, LoginManager, \
    login_user, login_required, logout_user, current_user
from flask.ext.bcrypt import Bcrypt
from flask_wtf import Form
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, \
    ValidationError
from wtforms.validators import DataRequired, Email

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
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

    def __init__(self, login_name, password, name, address, email):
        self.login_name = login_name
        self.password = flask_bcrypt.generate_password_hash(password)
        self.name = name
        self.address = address
        self.email = email

    def __repr__(self):
        return "<{}, {}>".format(self.login_name, self.role)

    def is_spacs_admin(self):
        return self.role == 'SPACSAdmin'

    def is_shop_admin(self):
        return self.role == 'PoolShopAdmin'

    def check_password(self, value):
        return flask_bcrypt.check_password_hash(self.password, value)


class PoolOwner(User, db.Model):
    __tablename__ = 'user'
    __table_args__ = {'useexisting': True}

    def __init__(self, login_name, password, name, address, email):
        super().__init__(login_name, password, name, address, email)
        self.role = 'PoolOwner'


class PoolShopAdmin(User, db.Model):
    __tablename__ = 'user'
    __table_args__ = {'useexisting': True}

    def __init__(self, login_name, password, name, address, email):
        super().__init__(login_name, password, name, address, email)
        self.role = 'PoolShopAdmin'


class SPACSAdmin(User, db.Model):
    __tablename__ = 'user'
    __table_args__ = {'useexisting': True}

    def __init__(self, login_name, password, name, address, email):
        super().__init__(login_name, password, name, address, email)
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


class NewPoolShop(Form):
    pass


class AddPoolForm(Form):
    def validate_username(self, field):
        if User.query.filter_by(login_name=field.data).first():
            raise ValidationError('Username already registered.')

    owner_username = StringField('User name', validators=[DataRequired(),
                                                          validate_username])
    owner_password = PasswordField('Password', validators=[DataRequired()])
    owner_name = StringField('Name', validators=[DataRequired()])
    owner_address = TextAreaField('Address', validators=[DataRequired()])
    owner_email = StringField('Email', validators=[DataRequired(), Email()])

    length = StringField('Length', validators=[DataRequired()])
    width = StringField('Width', validators=[DataRequired()])
    depth = StringField('Depth', validators=[DataRequired()])
    material = StringField('Pool Material', validators=[DataRequired()])
    pool_type = StringField('Pool Type', validators=[DataRequired()])
    submit = SubmitField('Add Pool')


class EditPoolForm(Form):
    length = StringField('Length', validators=[DataRequired()])
    width = StringField('Width', validators=[DataRequired()])
    depth = StringField('Depth', validators=[DataRequired()])
    material = StringField('Pool Material', validators=[DataRequired()])
    pool_type = StringField('Pool Type', validators=[DataRequired()])
    submit = SubmitField('Update Pool')


"""
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]

if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        post = Post(body=form.body.data,
                    author=current_user._get_current_object())
        db.session.add(post)
        return redirect(url_for('.index'))

        # Role.query.get(form.role.data)
"""


@app.route('/add-pool/', methods=['GET', 'POST'])
@login_required
def add_pool():
    form = AddPoolForm()
    if form.validate_on_submit():
        owner = PoolOwner(login_name=form.owner_username.data,
                          password=form.owner_password.data,
                          address=form.owner_address.data,
                          name=form.owner_name.data,
                          email=form.owner_email.data)
        db.session.add(owner)
        db.session.commit()
        owner = User.query.filter_by(
            login_name=form.owner_username.data).first()
        shop = Shop.query.filter_by(shop_admin_id=current_user.id).first()
        pool = Pool(length=form.length.data, width=form.width.data,
                    depth=form.depth.data, material=form.material.data,
                    pool_type=form.pool_type.data, shop_id=shop.id,
                    owner=owner.id)
        db.session.add(pool)
        db.session.commit()
        flash('The pool has been added.', 'success')
        return redirect(url_for('.pools'))

    return render_template('add_pool.html', form=form)


@app.route('/edit-pool/<int:pool_id>', methods=['GET', 'POST'])
@login_required
def edit_pool(pool_id):
    pool = Pool.query.get_or_404(pool_id)
    form = EditPoolForm(pool=pool)
    if form.validate_on_submit():
        pool.length = form.length.data
        pool.width = form.width.data
        pool.depth = form.depth.data
        pool.material = form.material.data  # Role.query.get(form.role.data)
        pool.pool_type = form.pool_type.data

        db.session.add(pool)
        flash('The pool has been updated.', 'success')
        return redirect(url_for('.pools'))

    form.length.data = pool.length
    form.width.data = pool.width
    form.depth.data = pool.depth
    form.material.data = pool.material
    form.pool_type.data = pool.pool_type

    return render_template('edit_pool.html', form=form, pool=pool)


@app.route('/delete-pool/<int:pool_id>', methods=['GET', 'POST'])
@login_required
def delete_pool(pool_id):
    pool = Pool.query.get_or_404(pool_id)
    db.session.delete(pool)
    flash('The pool has been deleted.', 'danger')
    return redirect(url_for('.pools'))


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
    if current_user.is_authenticated():
        flash('Already logged in, redirecting back to home.', 'warning')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/pools')
@login_required
def pools():
    if current_user.is_shop_admin():
        query = Pool.query.all()
        owners = PoolOwner.query.all()
        return render_template('pools.html', query=query, owners=owners)
    else:
        flash('This area is only for Pool Shop Administrators', 'warning')
        return redirect(url_for('index'))


@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)