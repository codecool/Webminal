import os, re, hashlib, base64, time
from datetime import datetime

from flask import Flask, url_for, render_template, render_template_string, safe_join, \
    request, flash, redirect, session, abort

from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.mail import Mail, Message
from flask.ext.flatpages import FlatPages, pygments_style_defs, pygmented_markdown
from flask.ext.bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
#from flask.ext.wtf import RecaptchaField
from wtfrecaptcha.fields import RecaptchaField 

from wtforms import Form, TextField, PasswordField, BooleanField, validators,SelectMultipleField,widgets

from smtplib import SMTPException

app = Flask(__name__.split('.')[0])

app.secret_key = '415\xf3~\xfeJ\x8b\xd4\x8e'
app.debug = True
RECAPTCHA_PUBLIC_KEY ='abcd'
RECAPTCHA_PRIVATE_KEY ='abcd'

if os.path.isfile('config.py'):
  app.config.from_pyfile('config.py')
else:
  app.config.from_pyfile('/var/www/webminal/config_default.py')

if app.config['USE_MYSQL']:
  app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://{username}:{password}@{host}/{database}'.format(
    username=app.config['MYSQL_USERNAME'],
    password=app.config['MYSQL_PASSWORD'],
    host=app.config['MYSQL_HOST'],
    database=app.config['MYSQL_DATABASE']
  )
else:
  app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{path}/database.db'.format(path=os.getcwd())

mail = Mail(app)
bcrypt = Bcrypt(app)
pages = FlatPages(app)
db = SQLAlchemy(app)



class RegistrationForm(Form):
  username = TextField('Username', [validators.Regexp(r'^[\w]+$'),validators.Length(min=4, max=14)])
  email = TextField('Email Address', [validators.Email(message='Invalid email address.')])
  
  password = PasswordField('New Password', [
    validators.Required(),
    validators.EqualTo('confirm', message='Passwords must match')
  ])
  
  confirm = PasswordField('Repeat Password')
  accept_tos = BooleanField('I accept the TOS', [validators.Required()])
  captcha = RecaptchaField(public_key='abcd',private_key='abcd',secure=False)

class LoginForm(Form):
  username = TextField('Username', [validators.Length(min=4, max=25), validators.Required()])
  password = PasswordField('Password', [validators.Required()])



class ResetLoginForm(Form):
  username = TextField('Username', [validators.Length(min=4, max=25)])
  email = TextField('Email Address', [validators.Email(message='Invalid email address.')])
  captcha = RecaptchaField(public_key='abcd',private_key='abcd',secure=False)


class ResetForm(Form):
  username = TextField('Username', [validators.Length(min=4, max=25)])
  email = TextField('Email Address', [validators.Email(message='Invalid email address.')])
  password = PasswordField('New Password', [
    validators.Required(),
    validators.EqualTo('confirm', message='Passwords must match')
  ])
  
  confirm = PasswordField('Repeat Password')

data = [('wmshell','Ubuntu'), ('wmawk','Fedora') ,  ('wmmysql','Slackware'),('wmmail','Arch')]
#data = [('wmshell','\n\n\nBash Commands/Shell script expert!'), ('wmawk','\n\n\nAwesome awk/sed guy') ,  ('wmmysql','\n\nDataBase geek'),('wmmail','\nUpdate me the new changes via rare mails')]

class ProfileForm(Form):
  example2 = SelectMultipleField(
        'Pick Things!',
        choices=data,
        option_widget=widgets.CheckboxInput(),
        widget=widgets.ListWidget(prefix_label=False)
        )
  example = BooleanField('Yeah, Count me in!')

class GroupForm(Form):
    grp_name = TextField(u'Group Name', [validators.Required()])


class GroupMemberForm(Form):
    email = TextField('Add member email',
                      [validators.Email(message='Invalid email address.'),
                       validators.Required()])

class LoginHistory(db.Model):
  __tablename__ = 'LoginHistory'
  uid = db.Column(db.Integer,primary_key=True)
  loginAt = db.Column(db.DateTime)
  userID = db.Column(db.Integer)

  def __init__(self,userID):
#   self.uid = uid
    self.loginAt = datetime.now()
    self.userID = userID

class UserProfile(db.Model):
  __tablename__ = 'UserProfile'
  nickname = db.Column(db.String(40), primary_key=True)
  wmshell  = db.Column(db.Boolean)
  wmawk = db.Column(db.Boolean)
  wmmysql = db.Column(db.Boolean)
  wmreserved = db.Column(db.Boolean)
  wmmail = db.Column(db.Boolean)

  def __init__(self,name):
    self.nickname = name
    self.wmshell  = 1
    self.wmawk = 0
    self.wmmysql = 0
    self.wmreserved = 0
    self.wmmail = 1 

  def __repr__(self):
    return '<UserProfile {username}>'.format(username=self.nickname)



class UserRemap(db.Model):
  __tablename__ = 'UserRemap'
  name = db.Column(db.String(40),primary_key=True)
  email = db.Column(db.String(255))
  password = db.Column(db.String(64))
  flag = db.Column(db.String(1))

  def __init__(self, name, email, password):
    self.email = email
    self.name = name
    self.password = password
    self.flag = 'N'

  def __repr__(self):
    return '<UserRemap {name}>'.format(name=self.name)



class User(db.Model):
  uid = db.Column(db.Integer, primary_key=True)
  nickname = db.Column(db.String(80), unique=True)
  email = db.Column(db.String(120), unique=True)
  password = db.Column(db.String(128))
  verify_key = db.Column(db.String(16), unique=True)
  verified = db.Column(db.Boolean)
  logins = db.Column(db.Integer)
  joinedOn = db.Column(db.DateTime)
  active = db.Column(db.Boolean)

  def __init__(self, username, email, password):
    self.email = email
    self.nickname = username
    self.password = password
#    self.salt = None
    self.verify_key = base64.urlsafe_b64encode(os.urandom(12))
    self.joinedOn = datetime.now()
    self.logins = 0
    
    self.verified = False
    self.active = False
    
  def create_account(self):
    # ADD USER CREATION CODE HERE
    self.set_password(self.password)

  def set_password(self, password):
#    self.salt = bcrypt.generate_password_hash(os.urandom(12), rounds=8)
#    self.password = bcrypt.generate_password_hash(self.salt + password, rounds=13)
     self.password = bcrypt.generate_password_hash(password, rounds=13)

  def verify_password(self, password):
#    return bcrypt.check_password_hash(self.password, self.salt + password)
     return bcrypt.check_password_hash(self.password, password)
  
  def generate_verify_key(self):
    self.verify_key = base64.urlsafe_b64encode(os.urandom(12))
    
    return self.verify_key
  
  def __repr__(self):
    return '<User {username}>'.format(username=self.nickname)


group_members = db.Table('group_members',
                         db.Column('member_id', db.Integer,
                                   db.ForeignKey('user.uid'),
                                   primary_key = True),
                         db.Column('grp_id', db.Integer,
                                   db.ForeignKey('group.grp_id'),
                                   primary_key = True)
               )

class Group(db.Model):
    grp_id = db.Column(db.Integer , primary_key = True)
    grp_name = db.Column(db.String(80) ,unique = True, nullable=False)
    grp_owner_uid = db.Column(db.Integer, db.ForeignKey('user.uid'),
                              unique=True, nullable=False)

    members = db.relationship('User', secondary=group_members,
                              backref=db.backref('groups', lazy='dynamic'))

    def __init__(self, name, owner_id):
        self.grp_name = name
        self.grp_owner_uid = owner_id


@app.route('/create_group/', methods=['POST'])
def create_group():
    user = User.query.filter(User.nickname==session['username']).first_or_404()
    form = GroupForm(request.form)
    if form.validate():
        grp = Group(form.grp_name.data, user.uid)
        db.session.add(grp)
        try:
            db.session.commit()
        except IntegrityError:
            form.grp_name.errors.append('Group Name already exists.')
            db.session.rollback()
            flash("Error")
        else:
            flash("Group created.")
            return redirect('profile')
    return render_template('profile.html', form=form,
                           member_form=GroupMemberForm())


@app.route('/edit_group/<int:grp_id>/', methods=['POST'])
def edit_group(grp_id):
    group = Group.query.get(grp_id)
    if group:
        form = GroupForm(request.form)
        if form.validate():
            group.grp_name = form.grp_name.data
            try:
                db.session.commit()
            except IntegrityError:
                form.grp_name.errors.append('Group Name already exists.')
                db.session.rollback()
                flash("Error")
            else:
                flash('Group name edited.')
                return redirect(url_for('profile'))
        return render_template('profile.html', edit=True, form=form,
                               grp_id=group.grp_id, member_form=GroupMemberForm())
    abort(404)


@app.route('/group/<int:grp_id>/add_member/', methods=['POST'])
def add_member(grp_id):
    group = Group.query.get(grp_id)
    if group:
        form = GroupMemberForm(request.form)
        if form.validate():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                group.members.append(user)
                try:
                    db.session.commit()
                except IntegrityError:
                    form.email.errors.append('Already added to the group.')
                    db.session.rollback()
                    flash("Error")
                else:
                    flash('Member added.')
                    return redirect('profile')
            else:
                form.email.errors.append('No such user exists.')
        return render_template('profile.html', edit=True, grp_id=group.grp_id,
                               member_form=form, form=GroupForm(obj=group),
                               members=group.members)

    abort(404)

@app.route('/profile/', methods=['GET'])
def profile():
    user = User.query.filter(User.nickname==session['username']).first_or_404()
    group = Group.query.filter(Group.grp_owner_uid==user.uid).all()
    grp_id = False
    if group:
        edit = True
        form = GroupForm(obj=group[0])
        members = group[0].members
    else:
        edit = False
        form = GroupForm()
        members = None
    if edit:
        grp_id = group[0].grp_id
    return render_template('profile.html', edit=edit, form=form,
                           grp_id=grp_id, members=members,
                           member_form=GroupMemberForm())


@app.route('/')
def index():
  return render_template('index.html')



@app.errorhandler(404)
def page_not_found(error):
  return render_template('404.html'), 404

@app.route('/about/')
def about():
  return render_template('about.html')

@app.route('/contact/')
def contact():
  return render_template('contact.html')

@app.route('/login/', methods=['GET', 'POST'])
def login():
  if 'user' in session:
    return redirect(url_for('index'))
  
  form = LoginForm(request.form)
  
  if request.method == 'POST' and form.validate():
    user = User.query.filter_by(nickname=form.username.data).first()
    
    if user:
      if user.verify_password(form.password.data):
        if not user.verified:
          flash('Your account has not been verified. Do you want to <a href="{url}">resend the email</a>?'.format(
            url=url_for('resend', verify_key=user.verify_key))
          )
          
          return render_template('login.html', form=form)
        
        #if not user.active:
	userremap=UserRemap.query.filter_by(name=user.nickname).first()

	if userremap:
	   flash('Please try again in a few minutes. Our admin is rushing to create an account for you!', category='error')
           return render_template('login.html', form=form)
        
        flash('You have been logged in')
        
        user.logins += 1
        
        db.session.add(LoginHistory(user.uid))
        db.session.commit()
        
        session['user'] = user
	session['username'] = form.username.data
	#retrieve profile and store them in a session
    	userprofile = UserProfile.query.filter_by(nickname=form.username.data).first()
	print "login===> userprofile:",userprofile
	if userprofile == None:
    		userprofile = UserProfile(form.username.data)
		db.session.add(userprofile)
        	db.session.commit()
	session['wmshell']=userprofile.wmshell
	session['wmawk']=userprofile.wmawk
	session['wmmysql']=userprofile.wmmysql
	session['wmmail']=userprofile.wmmail
	session['wmreserved']=userprofile.wmreserved
	print "login()~~>",userprofile.nickname,userprofile.wmshell,userprofile.wmawk,userprofile.wmmysql,userprofile.wmmail
        print "login - sess()~~>",session.get('wmshell'),session.get('wmawk'),session.get('wmmysql'),session.get('wmmail')
	print "wmreserved:",session.get('wmreserved')
        
        return redirect(url_for('index'))
    
    flash('Invalid username or password', category='error')
  
  return render_template('login.html', form=form)



@app.route('/logout/')
def logout():
  if 'user' in session:
    username=str(session['username'])
    session.pop('user', None)
    if username != "root" and username != "": 
	os.system("pkill -KILL -u"+username)
    flash('You have been logged out')
  
  return redirect(url_for('index'))


@app.route('/settings/save',methods=['GET','POST'])
def settings_save():
  if 'user' in session: 
    print "inside svave()"
    form=ProfileForm(request.form)
    if request.method == "POST" and form.validate():
        #username = form.username.data
	#print "username",form.username.data
	#print "checkbox",form.example.data
	print "checkbox",form.example2.data
    	#userprofile = UserProfile(form.username.data)
	#print "~~>",userprofile.nickname,userprofile.wmshell,userprofile.wmawk,userprofile.wmmysql,userprofile.wmmail
        flash('Your changes have been saved.')

	if form.example2.data:
	     for item in form.example2.data:
		print "item is :",item
		if "wmshell" in form.example2.data:
			session['wmshell']=True;
		else:
			session['wmshell']=False;
	
		if "wmawk" in form.example2.data:
			session['wmawk']= True;
		else:
			session['wmawk']= False;
		
		if "wmmysql" in form.example2.data:
			session['wmmysql']=True;
		else:
			session['wmmysql']= False;
		if "wmmail" in form.example2.data:
			session['wmmail']=True;
		else:
			session['wmmail']= False;
	else:
			print "empty ..brrr"
			session['wmshell']=False;
			session['wmawk']= False;
			session['wmmysql']= False;
			session['wmmail']= False;
	if form.example.data:
		session['wmreserved']=True;
	else:
		session['wmreserved']=False;
        print "setting()~~>",session.get('wmshell'),session.get('wmawk'),session.get('wmmysql'),session.get('wmmail')
	username=session.get('username')
	print "===> username:\n wmreserved:",username,session.get('wmreserved')
	
    	userprofile = UserProfile.query.filter_by(nickname=username).first()
	if userprofile == None:
		flash ("Unable to find record!")
	else:
    		#userprofile = UserProfile(session.get('username'))
		userprofile.wmshell=session['wmshell']
		userprofile.wmawk=session['wmawk']
		userprofile.wmmysql=session['wmmysql']
		userprofile.wmmail=session['wmmail']
		userprofile.wmreserved=session['wmreserved']
		#store session values -> db 
	#	db.session.add(userprofile)
	        db.session.commit()
#	print "save()~~>",userprofile.nickname,userprofile.wmshell,userprofile.wmawk,userprofile.wmmysql,userprofile.wmmail
	return render_template('settings.html',form = form)


@app.route('/settings/',methods=['GET','POST'])
def settings():
  if 'user' in session:
    username=session.get('username')
    print "-->",username,request.method

    print "setting()~~>",session.get('wmshell'),session.get('wmawk'),session.get('wmmysql'),session.get('wmmail'),session.get('wmreserved')
    form=ProfileForm()
    if request.method == "POST":# and form.validate():
	print "redirect_url"
        return redirect(url_for('save'))
    else:
    	print "render_template"
	chkbox=[]
	if session.get('wmshell'):
		chkbox.append('wmshell')
	if session.get('wmawk'):
		chkbox.append('wmawk')
	if session.get('wmmysql'):
		chkbox.append('wmmysql')
	if session.get('wmmail'):
		chkbox.append('wmmail')
 	if session.get('wmreserved'):
		form.example.data=session['wmreserved']		
	form.example2.data=chkbox
	return render_template('settings.html',form = form)
   



@app.route('/register/', methods=['GET', 'POST'])
def register():
  if 'user' in session:
    return redirect(url_for('index'))
  
  form = RegistrationForm(request.form,captcha={'ip_address' : request.remote_addr})
  
  if request.method == 'POST' and form.validate():
    if User.query.filter_by(nickname=form.username.data).first():
      flash('This username has already been taken', category='warning')
      return render_template('register.html', form=form)
    
    if User.query.filter_by(email=form.email.data).first():
      flash('An account already exists for the email address', category='warning')
      return render_template('register.html', form=form)
    
    user = User(form.username.data, form.email.data, form.password.data)
    userremap = UserRemap(form.username.data, form.email.data, form.password.data)
    
    db.session.add(user)
    db.session.add(userremap)
    db.session.commit()
    
    message = Message('Webminal Account Verification')
    message.add_recipient(user.email)
    message.sender = 'Administrator <efgadmin@webminal.org>'
    
    message.html = '''
      <p>Hello {username},</p>

      <p>Welcome to Webminal! Before you can begin using your account, you need to activate it using the below link:</p>


      <p><a href="http://www.webminal.org{verify_url}">Webminal Acccount Verfication URL</a></p>
      <p>
        Have a nice day,
        <br />
        The Webminal Team
      </p>
    '''
    
    message.html = message.html.format(
      username=user.nickname,
      verify_url=url_for('verify', verify_key=user.verify_key)
    )
    
    if app.config['MAIL']:
      try:
         mail.send(message)
      except SMTPException as error:
	 print "Mail FAILED",error
    else:
      print message.html
    
    flash('Thanks for registering. A email has been sent to "{email}" with a confirmation link.'.format(email=user.email))
    
    return redirect(url_for('login'))
  return render_template('register.html', form=form)



@app.route('/register/verify/<verify_key>/')
def verify(verify_key):
  if 'user' in session:
    return redirect(url_for('index'))
  
  user = User.query.filter_by(verify_key=verify_key, verified=False).first()
  
  if user:
    user.verified = True
    user.create_account()

    userremap = UserRemap.query.filter_by(name=user.nickname,flag='N').first()
    userremap.flag = 'Y'

    db.session.add(userremap)
    db.session.commit()  
    
    flash('Your account has been verified.Please check your inbox for futher details.')
    
    return redirect(url_for('login'))
  
  flash('Invalid verify key', category='error')
  return redirect(url_for('index'))



@app.route('/login/forgot/', methods=['GET', 'POST'])
def forgot():
  if 'user' in session:
    return redirect(url_for('index'))
  
  #form = ResetLoginForm(request.form)
  form  = ResetLoginForm(request.form,captcha={'ip_address' : request.remote_addr}) 
  
  if request.method == 'POST' and form.validate():
    user = User.query.filter_by(nickname=form.username.data, email=form.email.data).first()
    
    if not user:
      flash('The username or email incorrect')
      return render_template('forgot.html', form=form)
    
    message = Message('Webminal Account Password Reset')
    message.add_recipient(user.email)
    fun = 'Webminal Loves '+ user.nickname
#    message.sender = 'Administrator <efgadmin@webminal.org>'
    message.sender = fun + ' <efgadmin@webminal.org>'
    
    message.html = '''
      <p>Hello {username},</p>

      <p>You recently requested a password reset. Click the link below to reset your password:</p>

      <p><a href="http://www.webminal.org{reset_url}">Webminal Password Reset URL</a></p>

      <p>
        Have a nice day,
        <br />
        The Webminal Team
      </p>
    '''
    
    message.html = message.html.format(
      username=user.nickname,
      reset_url=url_for('reset', verify_key=user.generate_verify_key())
    )
    
    db.session.commit()
    
    if app.config['MAIL']:
      try:
         mail.send(message)
      except SMTPException as error:
	 print "mail failed",error
    else:
      print message.html
    
    flash('An email with reset instructions has been sent to your email address')
    return redirect(url_for('index'))
  
  return render_template('forgot.html', form=form)



@app.route('/register/reset/<verify_key>/', methods=['GET', 'POST'])
def reset(verify_key):
  if 'user' in session:
    return redirect(url_for('index'))
  
  form = ResetForm(request.form)
  
  if request.method == 'POST' and form.validate():
    user = User.query.filter_by(nickname=form.username.data, email=form.email.data, verify_key=verify_key).first()
    
    if not user:
      flash('The username or email incorrect')
      return render_template('reset.html', form=form, verify_key=verify_key)
    
    user.generate_verify_key()
    user.set_password(form.password.data)

    userremap = UserRemap(user.nickname, user.email, form.password.data)
    userremap.flag = 'P'
    db.session.add(userremap)
    db.session.commit()
    
    flash('Your password has been reset')
    return redirect(url_for('login'))
    
  return render_template('reset.html', form=form, verify_key=verify_key)



@app.route('/register/resend/<verify_key>/')
def resend(verify_key):
  user = User.query.filter_by(verify_key=verify_key).first()
  
  if not user:
    return render_template('resend.html', message='Your verification key is invalid')
  
  if user and not user.verified:
    message = Message('Webminal Account Re-Verification')
    message.add_recipient(user.email)
    message.sender = 'Administrator <efgadmin@webminal.org>'
    
    message.html = '''
      <p>Hello {username},</p>

      <p>You recently requested a new account verification link. Click the link below to verify your account:</p>
      <p><a href="http://www.webminal.org{verify_url}">Webminal Account Re-Verification URL</a></p>

      <p>
        Have a nice day,
        <br />
        The Webminal Team
      </p>
    '''
    
    message.html = message.html.format(
      username=user.nickname,
      verify_url=url_for('verify', verify_key=user.generate_verify_key())
    )
    
    db.session.commit()
    
    if app.config['MAIL']:
      try:
         mail.send(message)
      except SMTPException as error:
	 print "mail failed",error
    else:
      print message.html
    
    return render_template('resend.html', message='A new verification link was sent to your registered email')
  
  return render_template('index.html')  



@app.route('/terminal/')
def terminal():
  if 'user' in session:
    return render_template('terminal.html')
  
  flash('You must be logged in to use the online terminal', category='warning')
  return redirect(url_for('login'))



@app.route('/help/<command>/')
def help_command(command):
  return redirect(url_for('help_command_full', command=command))


@app.route('/help/<command>/plain/')
def help_command_plain(command):
  content = pages.get(command)
  
  if not content:
    return render_template('help_plain.html', content=pages.get('404'))
  
  return render_template('help_plain.html', content=content)


@app.route('/help/<command>/full/')
def help_command_full(command):
  content = pages.get(command)
  
  if not content:
    return render_template('404.html'), 404
  
  return render_template('help_full.html', content=content)



if __name__ == '__main__':
  app.run()