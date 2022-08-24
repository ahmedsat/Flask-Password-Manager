from flask import Flask, render_template, url_for, redirect,request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.widgets.core import PasswordInput
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

cipher=AESCipher(app.config['SECRET_KEY'])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    passwords = db.relationship('Password', backref='user', lazy=True)


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website  = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)






class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


class AddForm(FlaskForm):
    
    website = StringField(validators=[
                           InputRequired(), Length( max=255)], render_kw={"placeholder": "Website Name"})

    username = StringField(validators=[
                           InputRequired(), Length( max=255)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length( max=255)], render_kw={"placeholder": "Password"},widget=PasswordInput(hide_value=False))
    

    submit = SubmitField('Add')


@app.route('/')
def home():
  # db.create_all()
  # db.session.commit()
  login_status=current_user.is_authenticated

  return render_template('home.html',login_status=login_status)


@app.route('/login', methods=['GET', 'POST'])
def login():
  login_status=current_user.is_authenticated
  form = LoginForm()
  if form.validate_on_submit():
      user = User.query.filter_by(username=form.username.data).first()
      if user:
          if bcrypt.check_password_hash(user.password, form.password.data):
              login_user(user)
              return redirect(url_for('dashboard'))
  return render_template('login.html', form=form,login_status=login_status)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
  user_id=current_user.id
  login_status=current_user.is_authenticated
  data = Password.query.filter_by(user_id=user_id).all()
  for d in data:
    d.password = cipher.decrypt(d.password)
  return render_template('dashboard.html',login_status=login_status,results=data)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    login_status=current_user.is_authenticated

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form,login_status=login_status)


@ app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
  form = AddForm()
  login_status=current_user.is_authenticated
  user_id=current_user.id
  if form.validate_on_submit():
    websiteName = form.website.data
    username = form.username.data
    enc_password = cipher.encrypt(form.password.data)
    record = Password(username=username,website=websiteName,password=enc_password,user_id=user_id)
    db.session.add(record)
    db.session.commit()
    return redirect(url_for('dashboard'))

  return render_template('add.html', form=form,login_status=login_status)

@app.route('/delete')
@login_required
def delete():
  id=request.args.get('id')
  record = Password.query.get(id)
  if record:
    user_id=current_user.id
    if user_id == record.user_id:
      db.session.delete(record)
      db.session.commit()
  return redirect(url_for('dashboard'))


@ app.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    form = AddForm()
    id=request.args.get('id')
    record = Password.query.get(id)
    login_status=current_user.is_authenticated
    user_id=current_user.id

    if form.validate_on_submit():
        websiteName = form.website.data
        username = form.username.data
        enc_password = cipher.encrypt(form.password.data)
        record.website = websiteName
        record.username = username
        record.password = enc_password
        db.session.commit()
        return redirect(url_for('dashboard'))

    if record:
        user_id=current_user.id
        if user_id == record.user_id:
            record.password = cipher.decrypt(record.password)
            return render_template('update.html',\
                 form=form,login_status=login_status,formData=record)
    return redirect(url_for('dashboard'))
  
