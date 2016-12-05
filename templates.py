import os
import re
import jinja2
import webapp2
import hmac
import random
import hashlib

from string import letters

from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
	loader=jinja2.FileSystemLoader(
		template_dir
	), autoescape=True)

SECRET = 'i!l~ci(ms^ld$m!zf@of$kel2'

def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h== make_secure_val(val):
		return val

#Validation checks for username, password, email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Handler(webapp2.RequestHandler):
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user=uid and User.by_id(int(uid))
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

###user stuff
def make_salt():
	return ''.join(random.choice(letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt= make_salt()
	h = hashlib.sha256(name+pw+salt).hexdigest()
	return '%s,%s'%(salt,h)

def valid_pw(name, password, h):
	salt= h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def render_str(self, template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

class User(db.Model):
	"""User Information"""
	name = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid)

	@classmethod
	def by_name(cls, name):
		#user = db.GqlQuery("select * from User where name = '%s' limit 1"%(name))
	 	user = User.all().filter('name =', name).get()
	 	return user

	@classmethod
	def register(cls, username, password, email):
	 	pw_hash = make_pw_hash(username, password)
	 	return User(
	 		name = username,
	 		pw_hash=pw_hash,
	 		email=email)

	@classmethod
	def login(cls, name, pw):
		u= cls.by_name(name)
		
		if u and valid_pw(name, pw, u.pw_hash):
			return u
		
class SignUp(Handler):
	"""
	Sign up page
	"""
	def get(self):
		self.render("signup-form.html", user=self.user)

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(
			username = self.username,
			email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		#only case validation check
		if have_error:
			self.render('signup-form.html', **params)
		else:
			u=User.by_name(self.username)
			if u:
				error = 'That user name already exists'
				self.render('signup-form.html', error_username=error)
			else:
				u= User.register(self.username, self.password, self.email)
				u.put()

				self.login(u)
				self.redirect('/blog/welcome')


class Welcome(Handler):
    def get(self):
		if self.user:
			self.render('welcome.html', username = self.user.name, user=self.user)
		else:
			self.redirect('/blog/signup')

    def post(self):
    	self.redirect('/blog')


class Login(Handler):
	def get(self):
		self.render("login.html", user=self.user)

	def post(self):
		#check to see if it's valid username and password combination 
		username = self.request.get('username')
		password = self.request.get('password')

		#password to hash 
		#if it's username password_hash valid
		u = User.login(username, password)
		if u:
			#set coockie
			self.login(u)
			self.redirect('/blog')
			#self.redirect('/blog/login')
		else:
			error = 'Invalid Login. Check your ID and Password'
			self.render('login.html', error = error)

		#check to see if username is in the database <- already did it by checking coockie

		#then login 

class Logout(Handler):
	def get(self):
		self.logout()
		# uid = self.read_secure_cookie('user_id')
		# user = uid and User.by_id(int(uid))
		self.redirect('/blog')

class Article(db.Model):
	"""DB model for article"""
	title = db.StringProperty(required=True)
	date = db.DateTimeProperty(auto_now_add=True)
	text = db.TextProperty(required=True)
	last_modified = db.DateTimeProperty(auto_now=True)
	likes = db.IntegerProperty(required=True)
	who_liked = db.ListProperty(str)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("main.html", article = self)

	@classmethod
	def by_id(self, post_id):
		key = db.Key.from_path('Article', int(post_id))
		article = db.get(key)
		return article

class MainPage(Handler):
	"""Main Handler"""
	def get(self):
		#show up to 10 recent articles 
		articles = db.GqlQuery("select * from Article order by date desc limit 10")

		#find user from cookie... 
		# uid = self.read_secure_cookie("user_id")
		# user = uid and User.by_id(int(uid))
		self.render("main.html", articles = articles, user=self.user)

	def post(self):
		self.redirect("/blog/newpost")

class NewPost(Handler):
	"""New Post Handler"""
	def get(self):		
		self.render("new_post.html", user = self.user)

	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')
		
		#if subject and content filled
		if subject and content:
			article = Article(
				title=subject, 
				text=content,
				likes=0,
				who_liked=[])
			#put the article to db
			article.put()
			self.redirect('/blog/%s' % str(article.key().id()))
		else:
			#either subject or content missing
			error = "Subject or Content is missing"
			self.render(
				"new_post.html",
				title=subject,
				text=content,
				error=error,
				likes=0,
				who_liked=[])

class MadePost(Handler):
	"""Post Confirmation"""
	#article id undefined...
	def get(self, post_id):
		article = Article.by_id(post_id)
		if not article:
			self.error(404)
			return

		self.render(
			"permalink.html",
			article=article)

	def post(self, post_id):
		self.redirect('/blog')

class EditPost(Handler):
	def get(self, post_id):	
		#get post
		article = Article.by_id(post_id)
		if not article:
			self.error(404)
			return
		
		#send it to edit_post page. 
		self.render("edit_post.html", 
			text=article.text,
			title=article.title, 
			)
		
	def post(self, post_id):
		#get inputs
		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			article = Article.by_id(post_id)
			article.title = subject
			article.text = content
			#update db
			article.put()
			self.redirect('/blog/%s' % str(article.key().id()))
		else:
			#error check if either one is empty
			error = "Subject or Content is missing"

			self.render("edit_post.html", 
			title= subject,
			text=content,
			error=error)

class DeletePost(Handler):
	def get(self, post_id):
		#same rander behavior with Madepost (permanent link)
		article = Article.by_id(post_id)
		if not article:
			self.error(404)
			return

		self.render(
			"delete_post.html",
			article=article)

	def post(self, post_id):
		article = Article.by_id(post_id)
		perma_link = article.key().id()
		article.delete()
		# self.redirect("/blog/%s/delete_confirmation"%(permalink))	
		self.redirect("/blog")
class DeletePostConfirmation(Handler):
	def get(self, post_id):
		article = Article.by_id(post_id)
		title = article.title
		self.render(
			"delete_confirmation.html", title=title)
	def post(self):
		self.redirect('/blog')


class Admin(Handler):
	def get(self):
		self.render("admin.html")

	def post(self):
		for row in Article.all():
			row.delete()
		
		self.redirect('/blog')
app = webapp2.WSGIApplication([(
	'/blog',
	MainPage
), (
	'/blog/newpost',
	NewPost
), (
	'/blog/(\d+)',
	MadePost
), (
	'/blog/(\d+)/edit',
	EditPost
), (
	'/blog/(\d+)/delete',
	DeletePost
), (
	'/blog/(\d+)/delete_confirmation',
	DeletePostConfirmation
), (
	'/blog/signup',
	SignUp
), (
	'/blog/welcome',
	Welcome
), (
	'/blog/login',
	Login
), (
	'/blog/logout',
	Logout
), (
	'/admin',
	Admin
)], debug=True)

