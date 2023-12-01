# imports/modules must be downloaded before use (flask, mysql.connector, flask_bcrupt, python-dotenv)
# imports for: flask for web, flask_bcrypt for hashing password, mysql.connector to connect to mysql database, os and dotenv to get information from .env file
from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

# important module uses
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# initializes the database information
db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_DATABASE'),
}

def create_connection():
    return mysql.connector.connect(**db_config)

# takes you to the home page if you are signed in/in sesssion, else to the signin page
@app.route('/')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('signin'))

# sign up method which takes form request, hashes password, stores in database, and redirects you to sign in page on creation
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        connection = create_connection()
        cursor = connection.cursor()

        cursor.execute('SELECT * FROM login_information WHERE username=%s', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return render_template('signup.html', error='Username already taken.')

        cursor.execute('INSERT INTO login_information (username, password) VALUES (%s, %s)', (username, hashed_password))
        connection.commit()

        cursor.close()
        connection.close()

        return render_template('signin.html', success='Successfully signed up!')
    	
    return render_template('signup.html')

# sign in method which takes the form request, looks for user in database and checks for hashed password
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        connection = create_connection()
        cursor = connection.cursor()

        cursor.execute('SELECT * FROM login_information WHERE username=%s', (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[1], password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template('signin.html', error='Invalid username or password.')

    return render_template('signin.html')

# sign out page, removes from session and redirects you to the sign out page
@app.route('/signout')
def signout():
    session.pop('username', None)
    return redirect(url_for('signin'))

# runs the app
if __name__ == '__main__':
    app.run(debug=True, port=5501)
