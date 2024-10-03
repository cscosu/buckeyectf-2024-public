import numpy as np
from dataclasses import asdict

import app.forms as forms
from flask import render_template, redirect, request, url_for, abort, jsonify
from flask_login import current_user, login_user, logout_user, login_required
from config import SiteConfig
from app import app, db
import app.models as m

@app.route('/')
@app.route('/index')
def index():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        user = m.User.find(form.username.data)
        if not (user and user.checkpw(form.password.data)):
            return render_template('signup.html', title='Sign Up', form=form, error="Username or password invalid.")
        login_user(user,remember=True)
        return redirect(url_for('index'))
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/stats')
@login_required
def stats():
    return render_template('stats.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = forms.LoginForm()
    if form.validate_on_submit():
        if m.User.find(form.username.data):
            return render_template('signup.html', title='Sign Up', form=form, error="User already exists")
        user = m.User(username = form.username.data, score = 0)
        user.setpw(form.password.data)
        db.session.add(user)
        db.session.commit()
    return render_template('signup.html', title='Sign Up', form=form)


@app.route('/api/score/submit',methods=['POST'])
def parse_score():
    score = np.asarray([float(x) for x in request.json['counts']])
    avg = np.average(score)
    if avg == 0:
        {"status":"error","score":"-1"}
    avg = (60 / avg) / 5
    if current_user.is_anonymous:
        return {"status":"anonymous","score":avg}
    if avg < current_user.score:
        return {"status":"unimproved","score":avg}
    current_user.score = avg
    db.session.commit()
    score.tofile(SiteConfig.SCORES / f"{current_user.id:d}.score")
    return {"status":"improved", "score":avg}

@app.route('/api/score',methods=['GET'])
@login_required
def get_pb():
    if current_user.score == 0:
        return jsonify({'id':current_user.id,'score':[0],'best':0})
    user_score = np.fromfile(SiteConfig.SCORES / f"{current_user.id:d}.score").tolist()
    return jsonify({'id':current_user.id,'score':user_score,'best':current_user.score})

@app.route('/api/score/<int:id>',methods=['GET'])
def get_user(id):
    user = m.load_user(id)
    if "User" not in str(user):
        return jsonify({"error":"User does not exist."})
    return jsonify({'best':user.score})
