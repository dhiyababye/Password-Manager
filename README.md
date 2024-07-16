Password Manager Web Application
This is a web-based password manager application built with Flask, MySQL, Flask-Bcrypt, and Flask-Login. It allows users to securely register, log in, store, and retrieve passwords for different websites.

Features
User registration and login functionality with hashed passwords
Secure storage of passwords using encryption (Fernet symmetric encryption)
Password retrieval functionality
User authentication with Flask-Login
Requirements
Python 3.7+
Flask
Flask-Bcrypt
Flask-Login
mysql-connector-python
cryptography
Application Structure
app.py: Main application file containing routes and logic.
templates/: Directory containing HTML templates.
login.html: Template for the login page.
register.html: Template for the registration page.
menu.html: Template for the main menu after login.
addpassword.html: Template for adding a new password.
getpassword.html: Template for retrieving a password.
last.html: Template for displaying the retrieved password.
Usage
Register: Create a new user account.
Login: Log in with your username and password.
Add Password: Add a new password entry for a website.
Get Password: Retrieve the password for a specific website.
Security Considerations
Ensure the encryption_key.key file is securely stored and not exposed in version control.
Use a strong and unique app.secret_key.
Use secure passwords for database access and user accounts.
Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.
