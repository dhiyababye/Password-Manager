from flask import Flask, render_template, request, redirect, url_for
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required
import mysql.connector
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Generate or load the encryption key securely
key_file = 'encryption_key.key'

if os.path.exists(key_file):
    with open(key_file, 'rb') as f:
        key = f.read()
else:
    key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(key)

cipher_suite = Fernet(key)

# Connect to MySQL database
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="passwords"
)
cursor = conn.cursor(buffered=True)

# Define the User model
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# User loader function
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Routes

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor.execute('''SELECT id, password FROM login WHERE username = %s''', (username,))
        user = cursor.fetchone()
        if user and bcrypt.check_password_hash(user[1], password):  # Verify the password
            user_obj = User(user[0])
            login_user(user_obj)
            return redirect(url_for('menu'))
        else:
            error = "Invalid username or password."
        cursor.fetchall()  # Ensure all results are read
    return render_template('login.html', error=error)

@app.route('/menu')
@login_required
def menu():
    return render_template("menu.html")

@app.route('/add_password', methods=['POST','GET'])
@login_required
def add_password():
    if request.method == 'GET':
        return render_template('addpassword.html')
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        encrypted_password = cipher_suite.encrypt(password.encode('utf-8')).decode('utf-8')
        add_password_to_db(website, username, encrypted_password)
        return redirect(url_for('index'))  # Redirect back to the home page after adding password

def add_password_to_db(website, username, encrypted_password):
    sql = '''INSERT INTO passwordtable (website, username, password) VALUES (%s, %s, %s)'''
    val = (website, username, encrypted_password)
    cursor.execute(sql, val)
    conn.commit()

@app.route('/get_password', methods=['POST','GET'])
@login_required
def get_password():
    if request.method == 'GET':
        return render_template('getpassword.html')
    if request.method == 'POST':
        website = request.form['website']
        cursor.execute('''SELECT password FROM passwordtable WHERE website=%s''', (website,))
        encrypted_password = cursor.fetchone()
        cursor.fetchall()  # Ensure all results are read
        if encrypted_password:
            try:
                decrypted_password = cipher_suite.decrypt(encrypted_password[0].encode('utf-8')).decode('utf-8')
                return render_template('last.html', password=decrypted_password)
            except Exception as e:
                print(f"Decryption error: {e}")
                return "Error decrypting password."
        else:
            return render_template('invalid_website.html')  # Display invalid website message
    return render_template("getpassword.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute('''INSERT INTO login (username, password) VALUES (%s, %s)''', (username, hashed_password))
        conn.commit()
        return redirect(url_for('login'))
    return render_template('register.html', error=error)

if __name__ == '__main__':
    app.run(debug=True)

# Close connection to database
conn.close()
