import os
import re
import jinja2
import webapp2
import hmac
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


class Handler(webapp2.RequestHandler):
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


def render_str(self, template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

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

class SignUp(Handler):
	"""
	Sign up page
	"""
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		params = dict(
			username = username,
			email = email)

		if not valid_username(username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif password != verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			self.redirect('/blog/welcome?username=' + username)

class Article(db.Model):
	"""DB model for article"""
	title = db.StringProperty(required=True)
	date = db.DateTimeProperty(auto_now_add=True)
	text = db.TextProperty(required=True)
	last_modified = db.DateTimeProperty(auto_now=True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("main.html", article = self)

class User(db.Model):
	"""User Information"""
	name = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()
		

class MainPage(Handler):
	"""Main Handler"""
	def get(self):
		#show up to 10 recent articles 
		articles = db.GqlQuery("select * from Article order by date desc limit 10")
		self.render("main.html", articles = articles)

	def post(self):
		self.redirect("/blog/newpost")


class NewPost(Handler):
	"""New Post Handler"""
	def get(self):
		self.render("new_post.html")

	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')
		
		#if subject and content filled
		if subject and content:
			article = Article(
				title=subject, 
				text=content)
			#put the article to db
			article.put()
			self.redirect('/blog/%s' % str(article.key().id()))
		else:
			#either subject or content missing
			error = "Subject or Content is missing"
			self.render(
				"new_post.html",
				subject=subject,
				content=content,
				error=error)

class MadePost(Handler):
	"""Post Confirmation"""
	#article id undefined...
	def get(self, post_id):
		key = db.Key.from_path('Article', int(post_id))
		article = db.get(key)
		
		if not article:
			self.error(404)
			return

		self.render(
			"permalink.html",
			article=article, key=key, article_id=post_id)

	def post(self, post_id):
		self.redirect('/blog')

class Welcome(Handler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/blog/signup')

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
	'/blog/signup',
	SignUp
), (
	'/blog/welcome',
	Welcome
)], debug=True)
