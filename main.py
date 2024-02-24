import random
import os
from flask import Flask, render_template, request, redirect, make_response, flash
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

bcrypt = Bcrypt(app)

client = MongoClient('localhost', 27017)
db = client.wad

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    sessionid = request.cookies.get('sessionid', "")
    session = db.sessions.find_one({'sessionid': sessionid})

    if request.method == 'GET':
        if session is None:
            return redirect('/')
        else:
            email = session['email']
            user = db.users.find_one({'email': email})

            if 'firstname' in user:
                firstname = user['firstname']
            else:
                firstname = ''

            if 'lastname' in user:
                lastname = user['lastname']
            else:
                lastname = ''

            if 'filename' in user:
                filename = user['filename']
            else:
                filename = 'default_avatar.jpg'
            return render_template('profile.html', 
                                   email=email, 
                                   firstname=firstname, 
                                   lastname=lastname,
                                   filename=filename)
    
    if request.method == 'POST':
        email = session['email']

        firstname = request.form['firstname']
        lastname = request.form['lastname']
        db.users.update_one(
            {'email': email},
            {
                '$set': {
                'firstname': firstname,
                'lastname': lastname
            }
            }
        )
        
        resp = make_response(redirect('/profile'))
        return resp


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        sessionid = request.cookies.get('sessionid', "")
        session = db.sessions.find_one({'sessionid': sessionid})
        
        if session is not None:
            return redirect('/profile')
        else:
            return render_template('login.html')
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = db.users.find_one({'email': email})
        
        if user is not None and bcrypt.check_password_hash(user['password'], password):
            sessionid = str(random.randint(10**10, 10**20))
            db.sessions.insert_one({
                'sessionid': sessionid,
                'email': email
            })
            resp = make_response(redirect('/profile'))
            resp.set_cookie('sessionid', sessionid)
            return resp
        else:
            flash('Invalid email or password')
            return render_template('login.html')
        
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not email or not password:
            flash('Email and password cannot be empty')
            return redirect('/signup')

        user = db.users.find_one({'email': email})

        if user is not None:
            flash('Email is already exist')
            return redirect('/signup')
        
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            db.users.insert_one({
                'email': email,
                'password': hashed_password,
                'filename': 'default_avatar.jpg'
            })
            flash('Registered successfully')
            return redirect('/')
        
@app.route('/logout')
def logout():
    sessionid = request.cookies.get('sessionid', "")
    db.sessions.find_one_and_delete({'sessionid': sessionid})
    return redirect('/')

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    sessionid = request.cookies.get('sessionid', "")
    session = db.sessions.find_one({'sessionid': sessionid})
    email = session['email']

    if request.method == 'GET':
        return render_template('change-password.html')

    if request.method == 'POST':
        password = request.form['password']
        new_password_1 = request.form['new-password-1']
        new_password_2 = request.form['new-password-2']
        
        user = db.users.find_one({'email': email})
        if bcrypt.check_password_hash(user['password'], password):
            if new_password_1 == new_password_2:
                hashed_password = bcrypt.generate_password_hash(new_password_1).decode('utf-8')

                db.users.update_one(
                    {'email': email},
                    {
                        '$set': {
                        'password': hashed_password
                    }
                    }
                )
                return redirect('/profile')
            
            else:
                flash("Password confirmation doesn't match")
                return redirect('/change-password')

        else:
            flash('Invalid password')
            return redirect('/change-password')

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload-image', methods=['POST'])
def upload_image():
    sessionid = request.cookies.get('sessionid', "")
    session = db.sessions.find_one({'sessionid': sessionid})
    email = session['email']
    image = request.files['image']

    if image.filename == '':
        flash('No selected file')
        redirect('/profile')

    if image and allowed_file(image.filename):
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        db.users.update_one(
            {'email': email},
            {
                '$set': {
                'filename': filename
                }
            }
        )
        flash('Image uploaded successfully')
        return redirect('/profile')
    else:
        flash('File not allowed')
        return redirect('/profile')

if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)