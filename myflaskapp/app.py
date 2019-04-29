import io
import os
import pickle
import random
import numpy as np
import pandas as pd
from os import listdir
from flask import Response
from functools import wraps
from flask_mysqldb import MySQL
import matplotlib.pyplot as plt
from os.path import isfile, join
from sklearn import model_selection
from werkzeug import secure_filename
from matplotlib.figure import Figure
from passlib.hash import sha256_crypt
from sklearn.metrics import accuracy_score
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging

app = Flask(__name__)
    
# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '1234'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MYSQL
mysql = MySQL(app)

# Index
@app.route('/')
def index():
    return render_template('home.html')


# About
@app.route('/about')
def about():
    return render_template('about.html')

#view_reports
@app.route('/view_reports')
def view_reports():
    mypath = os.getcwd() + "\static"
    onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
    #for i in range(len(onlyfiles)):
     #   onlyfiles[i] = mypath+"\\" + onlyfiles[i]
      #  onlyfiles[i] = onlyfiles[i].replace('\\','/')
    return render_template('view_reports.html', plots = onlyfiles)

# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('file_upload'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

#file uploading
@app.route('/file_upload')
@is_logged_in
def file_upload():
    return render_template('file_upload.html')

#result page
@app.route('/result', methods = ['GET', 'POST'])
def result():
    if request.method == 'POST':
        f = request.files['file']
        f.save(secure_filename(f.filename))
        features = pd.read_csv(f.filename)
        for i in features.columns:
            df = features[i]
            mean = df[df != 0].mean()
            df[df == 0] = mean
        loaded_model = pickle.load(open("dengue-weights.dat", "rb"))
        y_pred = loaded_model.predict(features)
        predictions = [round(value) for value in np.exp(y_pred)]
        plt.plot(predictions)
        plt.title('Prediction')
        plt.savefig('static/Predictions.png')
        return render_template('result.html', data=predictions)

if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)
