from flask import Flask, render_template, redirect, url_for, flash, request, session
from mysqlconnection import MySQLConnector
import md5, os, binascii 

# Initialize application.
app = Flask(__name__)

# Setup session key.
app.secret_key = "RUBYISBETTER<3"

# Connect database.
mysql = MySQLConnector(app, 'the_wall')

# Helper methods
# Returns object containing hashed password and salt used.
def hash_password(password):
  salt =  binascii.b2a_hex(os.urandom(15))
  hashed_pw = md5.new(password + salt).hexdigest()
  data = {
    "digest": hashed_pw,
    "salt": salt
  }
  return data

# Authenticate user password.
def authenticate(user, password):
  salt = user['password_salt']
  hashed_pw = md5.new(password + salt).hexdigest()
  if user['password_digest'] == hashed_pw:
    return True
  return False

# Initialize session variables.
@app.before_first_request
def setup():
  session['current_user'] = None

# Home page.
@app.route('/')
def index():  # Ensure user is logged in.
  if not session['current_user'] == None:
    return redirect(url_for('wall'))
  return render_template('index.html')

# User log in.
@app.route('/login', methods = ['GET', 'POST'])
def login():
  if request.method == 'POST':
    email_address = request.form['email_address']
    password = request.form['password']

    user = mysql.query_db('SELECT * FROM users WHERE email = :email;', { "email": email_address })

    if not user:
      flash('Invalid email/password combination.', 'error')
      return redirect(url_for('login'))

    if authenticate(user[0], password):
      session['current_user'] = user[0]['id']
      return redirect(url_for('wall'))
    else:
      flash('Invalid email/password combination.', 'error')
      return redirect(url_for('login'))
  else:
    return render_template('login.html')

# User sign up.
@app.route('/register', methods = ['GET', 'POST'])
def register_get():
  if request.method == 'POST':
    email_address = request.form['email_address']
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    password = request.form['password']
    password_confirmation = request.form['password_confirmation']

    errors = []

    user = mysql.query_db('SELECT id FROM users WHERE email = :email;', { "email": email_address })
    # Can't be blank.
    # Loop through all attributes and capitalize/format name.
    for key in request.form:
      if len(request.form[key]) < 1:
        errors.append("{} can't be blank.".format(key.replace("_", " ")).capitalize())
      else:
        # First/last name must not include any numbers.
        if not first_name.isalpha():
          errors.append("First name can't contain numbers.")

        if not last_name.isalpha():
          errors.append("Last name can't contain numbers.")

    if user:
      errors.append('Email is invalid. (taken)')

    if len(errors):
      errors.sort()
      for message in errors:
        flash(message, 'error')
    else:
      digest_and_salt = hash_password(password)

      data = {
        "email": email_address,
        "first_name": first_name,
        "last_name": last_name,
        "password_digest": digest_and_salt['digest'],
        "password_salt": digest_and_salt['salt']
      }
      user_id = mysql.query_db('INSERT INTO users (email, first_name, last_name, password_digest, password_salt, created_at, updated_at) VALUES (:email, :first_name, :last_name, :password_digest, :password_salt, NOW(), NOW());', data)
      session['current_user'] = user_id
      return redirect(url_for('wall'))
    return redirect(url_for('register_get'))
  else:
    return render_template('register.html')

@app.route('/post', methods = ['POST'])
def post():
  title = request.form['title']
  content = request.form['content']
  errors = []

  if len(content) < 1:
    errors.append('Content cannot be blank.')
  
  if len(content) > 255:
    errors.append('Content cannot be longer than 255.')

  # Gaurd clause
  if errors:
    for message in errors:
      flash(message, 'error')
    return redirect(url_for('wall'))

  data = {
    "title": title,
    "user_id": session['current_user'],
    "content": content
  }
  # Hit database
  mysql.query_db('INSERT INTO posts (title, user_id, content, updated_at, created_at) VALUES (:title, :user_id, :content, NOW(), NOW());', data)
  
  return redirect(url_for('wall'))

@app.route('/comment/<id>', methods = ['DELETE'])
def delete_comment(id):
  mysql.query_db('DELETE FROM comments WHERE comment.id = :id;', { "id": id })
  return redirect(url_for('wall'))

@app.route('/post/<id>', methods = ['DELETE'])
def delete_post(id):
  mysql.query_db('DELETE FROM comments WHERE comment.post_id = :id;', { "id": id })
  mysql.query_db('DELETE FROM posts WHERE post.id = :id;', { "id": id })
  return redirect(url_for('wall'))

@app.route('/comment/<post_id>', methods = ['POST'])
def comment(post_id):
  content = request.form['content']
  errors = []
  if len(content) < 1:
    errors.append('Comment cannot be blank.')
  
  # Gaurd clause
  if errors:
    for message in errors:
      flash(message, 'error')
    return redirect(url_for('wall'))
  
  data = {
    "content": content,
    "user_id": session['current_user'],
    "post_id": post_id
  }
  mysql.query_db('INSERT INTO comments (content, user_id, post_id, created_at, updated_at) VALUES (:content, :user_id, :post_id, NOW(), NOW());', data)
  return redirect(url_for('wall'))

# Logged in users only!
@app.route('/wall')
def wall():
  # Ensure user is logged in.
  if session['current_user'] == None:
    flash('You are not logged in!', 'error')
    return redirect(url_for('index'))

  posts = mysql.query_db('SELECT *, CONCAT_WS(" ", users.first_name, users.last_name) AS full_name FROM posts JOIN users ON posts.user_id = users.id ORDER BY posts.created_at DESC')
  comments = mysql.query_db('SELECT *, CONCAT_WS(" ", users.first_name, users.last_name) AS full_name FROM comments JOIN users ON comments.user_id = users.id')

  # Show wall to logged in user.
  return render_template('wall.html', posts = posts, comments = comments)

@app.route('/logout')
def logout():
  session['current_user'] = None
  return redirect(url_for('index'))

app.run(debug=True)
