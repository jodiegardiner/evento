from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

# Initialize the Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with your secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///events.db'  # Replace with your database URI

# Initialize the database and other extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# User class for managing users and login sessions
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}')"


# Event class for managing events
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Add foreign key to link events to users
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('events', lazy=True))

    def __repr__(self):
        return f"Event('{self.title}', '{self.date}')"


# Create the database tables before the first request
@app.before_first_request
def create_tables():
    db.create_all()


# Dummy admin user for demonstration purposes
def create_admin():
    admin = User(username='admin', password=bcrypt.generate_password_hash('admin').decode('utf-8'))
    db.session.add(admin)
    db.session.commit()


# Initialize the login manager to handle user sessions
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes for login and events
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Please check your username and password.', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return render_template('index.html', events=current_user.events)


# Dummy route to add events (you can modify this to handle event creation)
@app.route('/add_event')
@login_required
def add_event():
    event = Event(title='Sample Event', description='This is a sample event.', user_id=current_user.id)
    db.session.add(event)
    db.session.commit()
    flash('Event added successfully!', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        create_admin()  # Create the admin user if it doesn't exist

    app.run(debug=True)
