import requests, random
from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

# from flask_socketio import SocketIO, send


app = Flask(__name__)
db = SQLAlchemy()
bcrypt = Bcrypt(app)
app.app_context().push()
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///final.db"
app.config["SECRET_KEY"] = "secretkey"
# app.config["SECRET"] = "secret"

db.init_app(app)

# socketio = SocketIO(app, cors_allowed_origins="*")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    likes = db.relationship('Like', foreign_keys='Like.user_id', backref='user', lazy='dynamic')
    admins = db.relationship('Admin', backref='user')

    def like_anime(self, anime):
        if not self.has_liked_anime(anime):
            like = Like(user_id=self.id, anime_id=anime.id)
            db.session.add(like)

    def unlike_anime(self, anime):
        if self.has_liked_anime(anime):
            Like.query.filter_by(
                user_id=self.id,
                anime_id=anime.id).delete()

    def has_liked_anime(self, anime):
        return Like.query.filter(
            Like.user_id == self.id,
            Like.anime_id == anime.id).count() > 0


class Anime(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    animeTitle = db.Column(db.String, nullable=False, unique=True)
    poster = db.Column(db.String)
    originalTitle = db.Column(db.String)
    synopsis = db.Column(db.String)
    likes = db.relationship('Like', backref='anime', lazy='dynamic')


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    anime_id = db.Column(db.Integer, db.ForeignKey('anime.id'), nullable=False)


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Integer, unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


with app.app_context():
    db.create_all()


# @socketio.on('message')
# def handle_message(message):
#     print("Received message: " + message)
#     if message != "User connected!":
#         send(message, broadcast=True)


@app.route('/')
def home():
    # titles = [11, 42765]
    # im = random.choice(titles)
    # # ima = request.form[im]
    # url1 = f'https://media.kitsu.io/anime/cover_images/{im}/large.jpg'
    # q = requests.get(url1)
    # # resp = q.json()
    # # image = resp['data'][0]['coverImage']['original']

    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                if user.admins:
                    return redirect(url_for('administration'))
                else:
                    return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/administration', methods=['GET', 'POST'])
@login_required
def administration():
    return render_template('administration.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/result', methods=['GET', 'POST'])
def result():
    anime = request.form['anime']
    url = f'https://kitsu.io/api/edge/anime?filter[text]={anime}'
    r = requests.get(url)
    response = r.json()
    animeTitle = response['data'][0]['attributes']['titles']['en_jp']
    poster = response['data'][0]['attributes']['posterImage']['small']
    originalTitle = response['data'][0]['attributes']['titles']['ja_jp']
    synopsis = response['data'][0]['attributes']['synopsis']

    if Anime.query.filter_by(animeTitle=anime.title()).first() is None:
        anime1 = Anime(animeTitle=animeTitle, poster=poster, originalTitle=originalTitle, synopsis=synopsis)
        db.session.add(anime1)
        db.session.commit()
        return render_template('result.html', animeTitle=animeTitle,
                               poster=poster,
                               originalTitle=originalTitle,
                               synopsis=synopsis
                               )
    else:
        return render_template('result.html', animeTitle=animeTitle,
                               poster=poster,
                               originalTitle=originalTitle,
                               synopsis=synopsis
                               )


@app.route('/like/<int:anime_id>/<action>')
@login_required
def like_action(anime_id, action):
    anime = Anime.query.filter_by(id=anime_id).first_or_404()
    if action == 'like':
        current_user.like_anime(anime)
        db.session.commit()
    if action == 'unlike':
        current_user.unlike_anime(anime)
        db.session.commit()
    return render_template('dashboard.html')


@app.errorhandler(IndexError)
def emptyLine(error):
    return render_template('error.html')


if __name__ == '__main__':
    app.run(debug=True)
