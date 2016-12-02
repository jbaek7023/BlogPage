import os
import jinja2
import webapp2
from string import letters

from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
	loader=jinja2.FileSystemLoader(
		template_dir
	), autoescape=True)


class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

def render_str(self, template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)


class Article(db.Model):
	"""DB model for article"""
	title = db.StringProperty(required=True)
	date = db.DateTimeProperty(auto_now_add=True)
	text = db.TextProperty(required=True)
	last_modified = db.DateTimeProperty(auto_now=True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("main.html", article = self)

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
	"""New Post Handler"""
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


app = webapp2.WSGIApplication([(
	'/blog',
	MainPage
), (
	'/blog/newpost',
	NewPost
), (
	'/blog/(\d+)',
	MadePost
)], debug=True)
