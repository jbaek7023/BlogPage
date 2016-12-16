import os
import re
import jinja2
import webapp2
import hmac
import random
import hashlib

from string import letters
from google.appengine.ext import db

# import Models
from model.user import User
from model.article import Article
from model.comment import Comment


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(
        template_dir
        ),
    autoescape=True)

SECRET = 'i!l~ci(ms^ld$m!zf@of$kel2'

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def valid_username(username):
    return username and re.compile(r"^[a-zA-Z0-9_-]{3,20}$").match(username)


def valid_password(password):
    return password and re.compile(r"^.{3,20}$").match(password)


def valid_email(email):
    return not email or re.compile(r'^[\S]+@[\S]+\.[\S]+$').match(email)

class Handler(webapp2.RequestHandler):
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

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


class SignUp(Handler):
    def get(self):
        self.render("signup-form.html", user=self.user)

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(
            username=self.username,
            email=self.email)

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

        # only case validation check
        if have_error:
            self.render('signup-form.html', **params)
        else:
            u = User.by_name(self.username)
            if u:
                error = 'That user name already exists'
                self.render('signup-form.html', error_username=error)
            else:
                u = User.register(self.username, self.password, self.email)
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
		if 'signup' in self.request.POST:
			self.redirect('/blog/signup')
		elif 'login' in self.request.POST:
			u = User.login(username, password)
			if u:
				#set coockie
				self.login(u)
				self.redirect('/blog')
			else:
				error = 'Invalid Login. Check your ID and Password'
				self.render('login.html', error = error)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class MainPage(Handler):
    def get(self):
        # show up to 10 recent articles
        q = "select * from Article order by date desc limit 10"
        articles = db.GqlQuery(q)
        # find user from cookie...
        uid = self.read_secure_cookie("user_id")
        self.render("main.html", articles=articles, uid=uid, user=self.user)

    def post(self):
        self.redirect("/blog/newpost")


class Like(Handler):
    def get(self, post_id):
        if self.user:
            article = Article.by_id(post_id)

            # checking if the article has the user on the who-liked list
            uid = self.read_secure_cookie('user_id')
            
            if uid in article.who_liked:
                # user can't fall into this if clause since use won't see the like button
                self.redirect('/blog/broken')
                return
            else:
                # add uid to who_liked array
                article.who_liked.append(uid)
                article.likes = article.likes+1
                article.put()
                self.render('liked.html', user=self.user)
        else:
            self.error = "You have to login to like the post"
            self.redirect("/blog/login")

    def post(self, post_id):
        if self.user:
            self.redirect('/blog')


class Unlike(Handler):
    def get(self, post_id):
        if self.user:
            article = Article.by_id(post_id)
            uid = self.read_secure_cookie('user_id')

            if uid in article.who_liked:
                # delete uid from who_liked array
                article.who_liked.remove(uid)
                article.likes -= 1
                article.put()
                self.render('disliked.html', user=self.user)
            else:
                self.redirect('/blog/broken')
                return
        else:
            self.redirect('/blog/broken')

    def post(self, post_id):
        if self.user:
            self.redirect('/blog')


class NewPost(Handler):
    """New Post Handler"""
    def get(self):
        # render only if user logged in
        if self.user:
            self.render("new_post.html", user=self.user)
        else:
            self.error = "You have to login to post"
            self.redirect("/blog/login")

    def post(self):
        if self.user:
            if 'main' in self.request.POST:
                self.redirect('/blog')
            elif 'sub' in self.request.POST:
                subject = self.request.get('subject')
                content = self.request.get('content')

                # created by someone. someone should be unique
                uid = self.read_secure_cookie('user_id')
                # if subject and content filled
                if subject and content:
                    article = Article(
                        title=subject,
                        text=content,
                        likes=0,
                        who_liked=[],
                        created_by=uid)
                    # put the article to db
                    article.put()
                    self.redirect('/blog/%s' % str(article.key().id()))
                else:
                    # either subject or content missing
                    error = "Subject or Content is missing"
                    self.render(
                        "new_post.html",
                        title=subject,
                        text=content,
                        error=error,
                        likes=0,
                        who_liked=[],
                        created_by=uid)
        else:
            self.redirect('/blog/login')
		

class MadePost(Handler):
    def get(self, post_id):
        if self.user:
            article = Article.by_id(post_id)
            if not article:
                self.redirect(
                	'/blog/broken')
                return

            self.render(
                "permalink.html",
                article=article,
                name=self.user.name,user=self.user)
        else:
            self.error = "You have to login to see the post"
            self.redirect("/blog/login")

    
    def post(self, post_id):
        if self.user:
            self.redirect('/blog')
        else:
            self.redirect('/blog/login')


class EditPost(Handler):
    def get(self, post_id):
        if self.user:
            article = Article.by_id(post_id)

            if not article:
                self.redirect('/blog/broken')
                return

            # prevent anonymous logged in user from accessing edit
            # post by url:/blog/98792739/edit
            uid = self.read_secure_cookie('user_id')

            if article.created_by == uid:
                # send it to edit_post page.
                self.render(
                    "edit_post.html",
                    text=article.text,
                    title=article.title,
                    user=self.user)
            else:
                self.redirect('/blog/broken')
                return
        else:
            self.redirect('/blog/login')
            return

    def post(self, post_id):
        if self.user:
            if 'main' in self.request.POST:
                self.redirect('/blog')
            elif 'sub' in self.request.POST:
                # get inputs
                subject = self.request.get('subject')
                content = self.request.get('content')
                article = Article.by_id(post_id)
                uid = self.read_secure_cookie('user_id')
    
                if article.created_by == uid:
                    
                    if subject and content:
                        article.title = subject
                        article.text = content
                        article.put()
                        self.redirect('/blog/%s' % str(article.key().id()))
                    else:
                        # error check if either one is empty
                        error = "Subject or Content is missing"
                        self.render(
                            "edit_post.html",
                            title=subject,
                            text=content,
                            error=error)
                else:
                    self.redirect('/blog/broken')
        else:
            self.redirect('/blog/login')
            return


class DeletePost(Handler):
    def get(self, post_id):
        if self.user:
            article = Article.by_id(post_id)

            if not article:
                self.redirect('/blog/broken')
                return

            uid = self.read_secure_cookie('user_id')

            if article.created_by == uid:
                # send it to edit_post page.
                self.render(
                    "delete_post.html",
                    article=article,
                    user=self.user)
            else:
                self.redirect('/blog/broken')
                return
        else:
            self.redirect('/blog/login')
            return

    def post(self, post_id):
        if self.user:   
            if 'back_2_main' in self.request.POST:
                self.redirect('/blog')
            elif 'delete_post' in self.request.POST:
                article = Article.by_id(post_id)
                uid = self.read_secure_cookie('user_id')

                if article.created_by == uid:
                    perma_link = article.key().id()
                    article.delete()
                    self.redirect("/blog/%s/delete_confirmation" % (perma_link))
                else:
                    self.redirect('/blog/broken')
                    return
        else:
            self.redirect('/blog/login')
            return


class DeletePostConfirmation(Handler):
    def get(self, post_id):
        if self.user:
            article = Article.by_id(post_id)
            uid = self.read_secure_cookie('user_id')

            if article.created_by == uid:
                self.render(
                    "delete_confirmation.html")
            else:
                self.redirect('/blog/broken')
        else:
            self.redirect('/blog/login')
    def post(self, post_id):
        if self.user:
            article = Article.by_id(post_id)
            uid = self.read_secure_cookie('user_id')

            if article.created_by == uid:
                self.render('/blog')
            else:
                self.redirect('/blog/broken')
        else:
            self.redirect('/blog/login')

	
class NewComment(Handler):
    def get(self, post_id):
        if self.user:
            # get post
            article = Article.by_id(post_id)
            if not article:
                self.redirect('/blog/broken')
                return
            # render post
            self.render(
                "new_comment.html",
                title=article.title,
                user=self.user)
        else:
            self.error = "You have to login to see the post"
            self.redirect("/blog/login")

    def post(self, post_id):
        if self.user:
            if 'main' in self.request.POST:
                self.redirect('/blog/%s' % str(post_id))
            elif 'sub' in self.request.POST:
                comment_text = self.request.get('comment')
                comment_elem = Comment(
                    comment=comment_text,
                    post_id=post_id,
                    made_by=self.user.name)
                comment_elem.put()

                self.redirect('/blog/%s' % str(post_id))
        else:
            self.redirect('/blog/login')


class EditComment(Handler):
    def get(self, post_id, comment_id):
        if self.user:
            # get current comment!
            article = Article.get_by_id(int(post_id))
            comment = Comment.get_by_id(int(comment_id))
            if comment.made_by == self.user.name:
                self.render(
                    "edit_comment.html",
                    title=article.title,
                    comment=comment.comment,
                    user=self.user)
            else:
                self.redirect('/blog/broken')
        else:
            self.redirect('/blog/login')

    def post(self, post_id, comment_id):
        if self.user:
            article = Article.get_by_id(int(post_id))
            comment_elem = Comment.get_by_id(int(comment_id))
            if comment_elem.made_by == self.user.name:
                if 'main' in self.request.POST:
                    self.redirect('/blog/%s' % str(post_id))
                elif 'sub' in self.request.POST:
                    comment_elem.comment = self.request.get('comment')
                    comment_elem.put()
                    self.redirect('/blog/%s' % str(post_id))
            else:
                self.redirect('/blog/broken')
        else:
            self.redirect('/blog/login')


class DeleteComment(Handler):
    def get(self, post_id, comment_id):
        if self.user:
            # get current comment!
            article = Article.get_by_id(int(post_id))
            comment = Comment.get_by_id(int(comment_id))

            if comment.made_by == self.user.name:
                self.render(
                    "delete_comment.html",
                    title=article.title,
                    comment=comment.comment,
                    user=self.user)
            else:
                self.redirect('/blog/broken')
        else:
            self.redirect('/blog/login')

    def post(self, post_id, comment_id):
        if self.user:
            article = Article.get_by_id(int(post_id))
            comment_elem = Comment.get_by_id(int(comment_id))
            
            if comment_elem.made_by == self.user.name:
                if 'back' in self.request.POST:
                    self.redirect('/blog/%s' % str(post_id))
                elif 'delete' in self.request.POST:
                    comment_elem.delete()
                    self.redirect('/blog/%s' % str(post_id))
            else:
                self.redirect('/blog/broken')
        else:
            self.redirect('/blog/login')
        

class Admin(Handler):
    '''DELETE ALL COMMENTS AND ARTICLES '''
    def get(self):
        self.render("admin.html")

    def post(self):
        for row in Article.all():
            row.delete()

        for row in Comment.all():
            row.delete()
            self.redirect('/blog')


class Broken(Handler):
    def get(self):
        self.render("broken_link.html")


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
    '/blog/(\d+)/like',
    Like
), (
    '/blog/(\d+)/unlike',
    Unlike
), (
    '/blog/login',
    Login
), (
    '/blog/logout',
    Logout
), (
    '/admin_secret777',
    Admin
), (
    '/blog/(\d+)/new_comment',
    NewComment
), (
    '/blog/(\d+)/(\d+)/edit_comment',
    EditComment
), (
    '/blog/(\d+)/(\d+)/delete_comment',
    DeleteComment
), (
    '/blog/broken',
    Broken
)], debug=False)
