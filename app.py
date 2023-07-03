from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a secure secret key.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///events.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Event model representing the events table in the database.
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# User model representing the users table in the database.
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"User('{self.username}')"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Home page, displays the events calendar and allows users to add events.
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        event_title = request.form['event']
        new_event = Event(title=event_title, user_id=current_user.id)
        db.session.add(new_event)
        db.session.commit()
        return redirect(url_for('index'))

    events = Event.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', events=events, current_user=current_user)


# Login page, handles user login.
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))

    return render_template('login.html')


# Logout endpoint, clears the current_user variable.
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Create the database tables if they do not exist.
    db.create_all()
    app.run(debug=True)

