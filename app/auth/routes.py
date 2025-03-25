from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from app.models import db

from app.auth import bp
from app.models import User
from app.auth.forms import LoginForm, RegistrationForm, ProfileForm
from flask import Blueprint
bp = Blueprint('auth', __name__)
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('auth.login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    return render_template('auth/login.html', title='Sign In', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user! Please complete your profile.')
        return redirect(url_for('auth.complete_profile'))
    return render_template('auth/signup.html', title='Register', form=form)

@bp.route('/complete_profile', methods=['GET', 'POST'])
@login_required
def complete_profile():
    form = ProfileForm()
    if form.validate_on_submit():
        current_user.full_name = form.full_name.data
        current_user.company = form.company.data
        db.session.commit()
        flash('Your profile has been updated.')
        return redirect(url_for('main.index'))
    elif request.method == 'GET':
        form.full_name.data = current_user.full_name
        form.company.data = current_user.company
    return render_template('auth/complete_profile.html', title='Complete Profile', form=form)