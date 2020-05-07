from flask import Flask, render_template, flash, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy as _BaseSQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from functools import wraps
from sqlalchemy import or_, func
import random
import pymysql
import secrets
import os

#dbuser=os.environ.get('DBUSER')
#dbpass=os.environ.get('DBPASS')
#dbhost=os.environ.get('DBHOST')
#dbname=os.environ.get('DBNAME')


conn = "mysql+pymysql://{0}:{1}@{2}/{3}".format(secrets.dbuser, secrets.dbpass, secrets.dbhost, secrets.dbname)
#conn="mysql+pymysql://{0}:{1}@{2}/{3}".format(dbuser,dbpass,dbhost,dbname)
# Open database connection
dbhost = secrets.dbhost
dbuser = secrets.dbuser
dbpass = secrets.dbpass
dbname = secrets.dbname

#db = pymysql.connect(dbhost, dbuser, dbpass, dbname)

app = Flask(__name__)

login = LoginManager(app)
login.login_view = 'login'
login.login_message_category = 'danger' # sets flash category for the default message 'Please log in to access this page.'


app.config['SECRET_KEY']='SuperSecretKey'
# import os
# = os.environ.get('SECRET_KEY')


# Prevent --> pymysql.err.OperationalError) (2006, "MySQL server has gone away (BrokenPipeError(32, 'Broken pipe')
class SQLAlchemy(_BaseSQLAlchemy):
     def apply_pool_defaults(self, app, options):
        super(SQLAlchemy, self).apply_pool_defaults(app, options)
        options["pool_pre_ping"] = True
# <-- MWC


app.config['SQLALCHEMY_DATABASE_URI'] = conn
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # silence the deprecation warning
db = SQLAlchemy(app)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class NewUserForm(FlaskForm):
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    access = IntegerField('Access: ')
    submit = SubmitField('Create User')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')


class UserDetailForm(FlaskForm):
    id = IntegerField('Id: ')
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    access = IntegerField('Access: ')

class AccountDetailForm(FlaskForm):
    id = IntegerField('Id: ')
    name = StringField('Name: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])


class PostForm(FlaskForm):
    postid = IntegerField('Post ID:')
    movie=StringField('Movie Title:', validators=[DataRequired()])
    myr=IntegerField('Movie Year:', validators=[DataRequired()])
    mimg=StringField('Movie Poster:', validators=[DataRequired()])
    song=StringField('Music Name:', validators=[DataRequired()])
    singer=StringField('Singer:', validators=[DataRequired()])
    simg=StringField('Album Image:', validators=[DataRequired()])
    quote=StringField('Quote:', validators=[DataRequired()])
    book=StringField('Book Title:', validators=[DataRequired()])
    writer=StringField('Writer:', validators=[DataRequired()])
    qimg=StringField('Book Image:', validators=[DataRequired()])


class xzhang270_post(db.Model):
    postid = db.Column(db.Integer, primary_key=True)
    movie=db.Column(db.String(100))
    myr=db.Column(db.Integer)
    mimg=db.Column(db.String(30))
    song=db.Column(db.String(100))
    singer=db.Column(db.String(100))
    simg=db.Column(db.String(40))
    quote=db.Column(db.String(1000))
    book=db.Column(db.String(100))
    writer=db.Column(db.String(100))
    qimg=db.Column(db.String(30))

    def __repr__(self):
        return '<Post {0}>'.format(self.postid)




ACCESS = {
    'guest': 0,
    'user': 1,
    'admin': 2
}

class User(UserMixin, db.Model):
    __tablename__ = 'xzhang270_users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    username = db.Column(db.String(30))
    password_hash = db.Column(db.String(128))
    access = db.Column(db.Integer)

    def __init__(self, name, email, username, access=ACCESS['guest']):
        self.id = ''
        self.name = name
        self.email = email
        self.username = username
        self.password_hash = ''
        self.access = access

    def is_admin(self):
        return self.access == ACCESS['admin']

    def is_user(self):
        return self.access == ACCESS['user']

    def allowed(self, access_level):
        return self.access >= access_level

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {0}>'.format(self.username)




@login.user_loader
def load_user(id):
    return User.query.get(int(id))  #if this changes to a string, remove int


### custom wrap to determine access level ###
def requires_access_level(access_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: #the user is not logged in
                return redirect(url_for('login'))

            #user = User.query.filter_by(id=current_user.id).first()

            if not current_user.allowed(access_level):
                flash('You do not have access to this resource.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator




#### Routes ####

# index
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', pageTitle='Flask App Home Page')

# about
#@app.route('/about')
#def about():
#    return render_template('about.html', pageTitle='About My Flask App')

# registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(name=form.name.data, username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html',  pageTitle='Register | My Flask App', form=form)

# user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        flash('You are now logged in', 'success')
        return redirect(next_page)
    return render_template('login.html',  pageTitle='Login | My Flask App', form=form)


#logout
@app.route('/logout')
def logout():
    logout_user()
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('index'))


################ GUEST ACCESS FUNCTIONALITY OR GREATER ###################

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    user = User.query.get_or_404(current_user.id)
    form = AccountDetailForm()

    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data
        user.set_password(form.password.data)

        db.session.commit()
        flash('Your account has been updated.', 'success')
        return redirect(url_for('account'))

    form.name.data = user.name
    form.email.data = user.email

    return render_template('account_detail.html', form=form, pageTitle='Your Account')

#first page for guest
@app.route('/guest_page')
def guest_page():
    return render_template('guest_page.html', pageTitle='Welcome as a Guest')


################ USER ACCESS FUNCTIONALITY OR GREATER ###################

# post cards
@app.route('/post')
def post():
    all_posts = xzhang270_post.query.all()
    rand = random.randint(1,5)
    return render_template('post.html', posts=all_posts, rand=rand, pageTitle='Post Cards')

# post design
@app.route('/post_design/<int:postid>', methods=['GET','POST'])
def post_design(postid):
    previd=0
    nextid=0
    maxid =db.session.query(db.func.max(xzhang270_post.postid)).scalar()
    id_tuple=db.session.query(xzhang270_post.postid).all()
    id_list= [value for (value,) in id_tuple]
    post = xzhang270_post.query.get_or_404(postid)
    postid=post.postid
    if postid>1:
        previd=id_list[id_list.index(postid)-1]
    if postid<maxid:
        nextid=id_list[id_list.index(postid)+1]
    movie=post.movie
    myr=post.myr
    mimg=post.mimg
    music=post.song
    artist=post.singer
    simg=post.simg
    quote=post.quote
    book=post.book
    writer=post.writer
    qimg=post.qimg
    return render_template('post_design.html',pageTitle='Movie·Music·Mood',
    maxid=maxid, previd=previd, nextid=nextid, postid=postid, movie=movie, myr=myr, mimg=mimg,music=music,artist=artist,
    simg=simg, quote=quote, book=book, writer=writer, qimg=qimg)



# search post (user version)
@app.route('/search_postcard', methods=['GET','POST'])
def search_postcard():
    if request.method=='POST':
        form=request.form
        search_value=form['search_string']
        search='%{}%'.format(search_value)
        results=xzhang270_post.query.filter(or_(xzhang270_post.movie.like(search),
                                                xzhang270_post.myr.like(search),
                                                xzhang270_post.song.like(search),
                                                xzhang270_post.singer.like(search),
                                                xzhang270_post.quote.like(search),
                                                xzhang270_post.book.like(search),
                                                xzhang270_post.writer.like(search))).all()
        flash('All search results are shown.','success')
        return render_template('post.html', posts=results, pageTitle='Search Results', legend='Search Results')
    else:
        return redirect('/post')




################ ADMIN ACCESS FUNCTIONALITY ###################

# control panel for users
@app.route('/all_users')
@requires_access_level(ACCESS['admin'])
def all_users():
    all_users = User.query.all()
    return render_template('all_users.html', users=all_users, pageTitle='All Users')

#control panel for posts
@app.route('/all_posts')
@requires_access_level(ACCESS['admin'])
def all_posts():
    all_posts = xzhang270_post.query.all()
    return render_template('all_posts.html', posts=all_posts, pageTitle='All Posts')


# user details & update
@app.route('/user_detail/<int:user_id>', methods=['GET','POST'])
@requires_access_level(ACCESS['admin'])
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDetailForm()
    form.id.data = user.id
    form.name.data = user.name
    form.email.data = user.email
    form.username.data = user.username
    form.access.data = user.access
    return render_template('user_detail.html', form=form, pageTitle='User Details')

# update user
@app.route('/update_user/<int:user_id>', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDetailForm()

    orig_user = user.username # get user details stored in the database - save username into a variable

    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data

        new_user = form.username.data

        if new_user != orig_user: # if the form data is not the same as the original username
            valid_user = User.query.filter_by(username=new_user).first() # query the database for the usernam
            if valid_user is not None:
                flash("That username is already taken...", 'danger')
                return redirect(url_for('all_users'))

        # if the values are the same, we can move on.
        user.username = form.username.data
        user.access = request.form['access_lvl']
        db.session.commit()
        flash('The user has been updated.', 'success')
        return redirect(url_for('all_users'))

    return redirect(url_for('all_users'))

# delete user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def delete_user(user_id):
    if request.method == 'POST': #if it's a POST request, delete the friend from the database
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted.', 'success')
        return redirect(url_for('all_users'))

    return redirect(url_for('all_users'))

# new user
@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    form = NewUserForm()

    if request.method == 'POST' and form.validate_on_submit():
        user = User(name=form.name.data, username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        user.access = request.form['access_lvl']
        db.session.add(user)
        db.session.commit()
        flash('User has been successfully created.', 'success')
        return redirect(url_for('login'))

    return render_template('new_user.html',  pageTitle='New User | My Flask App', form=form)


#add new post
@app.route('/add_post', methods=['GET','POST'])
def add_post():
    form = PostForm()
    if request.method == 'POST' and form.validate_on_submit():
        post=xzhang270_post(movie=form.movie.data, myr=form.myr.data, mimg=form.mimg.data,
        song=form.song.data, singer=form.singer.data, simg=form.simg.data,
        quote=form.quote.data, book=form.book.data, writer=form.writer.data, qimg=form.qimg.data)
        db.session.add(post)
        db.session.commit()
        flash('Post has been successfully added.', 'success')
        return redirect(url_for('all_posts'))

    return render_template('add_post.html', form=form, pageTitle='Add A New Post')


# search post (admin version)
@app.route('/search_post', methods=['GET','POST'])
def search_post():
    if request.method=='POST':
        form=request.form
        search_value=form['search_string']
        search='%{}%'.format(search_value)
        results=xzhang270_post.query.filter(or_(xzhang270_post.movie.like(search),
                                                xzhang270_post.myr.like(search),
                                                xzhang270_post.song.like(search),
                                                xzhang270_post.singer.like(search),
                                                xzhang270_post.quote.like(search),
                                                xzhang270_post.book.like(search),
                                                xzhang270_post.writer.like(search))).all()
        flash('All search results are shown.','success')
        return render_template('all_posts.html', posts=results, pageTitle='Search Results', legend='Search Results')
    else:
        return redirect('/all_posts')

#delete post
@app.route('/delete_post/<int:postid>', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def delete_post(postid):
    if request.method=='POST':
        post=xzhang270_post.query.get_or_404(postid)
        db.session.delete(post)
        db.session.commit()
        flash('User has been deleted.', 'success')
        return redirect(url_for('all_posts'))
    else:
        return redirect(url_for('all_posts'))

#post detail
@app.route('/post_detail/<int:postid>', methods=['GET','POST'])
@requires_access_level(ACCESS['admin'])
def post_details(postid):
    post = xzhang270_post.query.get_or_404(postid)
    form = PostForm()
    form.postid.data=post.postid
    form.movie.data=post.movie
    form.myr.data=post.myr
    form.mimg.data=post.mimg
    form.song.data=post.song
    form.singer.data=post.singer
    form.simg.data=post.simg
    form.quote.data=post.quote
    form.book.data=post.book
    form.writer.data=post.writer
    form.qimg.data=post.qimg
    return render_template('post_details.html', form=form, pageTitle='Post Details')



#update post
@app.route('/post/<int:postid>/update', methods=['GET','POST'])
@requires_access_level(ACCESS['admin'])
def update_post(postid):
    post=xzhang270_post.query.get_or_404(postid)
    form=PostForm()

    if form.validate_on_submit():
        post.movie=form.movie.data
        post.myr=form.myr.data
        post.mimg=form.mimg.data
        post.song=form.song.data
        post.singer=form.singer.data
        post.simg=form.simg.data
        post.quote=form.quote.data
        post.book=form.book.data
        post.writer=form.writer.data
        post.qimg=form.qimg.data
        db.session.commit()
        return redirect(url_for('all_posts'))
    form.postid.data=post.postid
    form.movie.data=post.movie
    form.myr.data=post.myr
    form.mimg.data=post.mimg
    form.song.data=post.song
    form.singer.data=post.singer
    form.simg.data=post.simg
    form.quote.data=post.quote
    form.book.data=post.book
    form.writer.data=post.writer
    form.qimg.data=post.qimg

    return redirect(url_for('all_posts'))


if __name__ == '__main__':
    app.run(debug=True)
