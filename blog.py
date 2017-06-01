# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from os import path
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db
secret = ''

template_dir = path.join(path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Handler
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

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

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

# New Functions like suggestion in Review
    def user_owns_post(self, post):
        return self.user.key == post.author

    def user_owns_comment(self, comment):
        return self.user.key == comment.author

    def post_exists(self, post):
        @wraps(function)
        def wrapper(self, post_id):
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            if post:
                return function(self, post_id, post)
            else:
                self.error(404)
                return
        return wrapper

    def comment_exists(self, comment):
        @wraps(function)
        def wrapper(self, comment_id):
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            if post:
                return function(self, comment_id, comment)
            else:
                self.error(404)
                return
        return wrapper

    def user_logged_in(self, user):
        return self.user.key == post.author # this is psuedo code


# Startpage
class Home(BlogHandler):
    def get(self):
        self.render('home.html')


# ROT13 Page
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text=rot13)


# Welcome Page
class Welcome(BlogHandler):
    def get(self):
        name = self.request.get('name')
        if valid_username(name):
            self.render('welcome.html',
                        name=name)
        else:
            return self.redirect('/signup')


# User & Security
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# Blog Stuff
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Comment(db.Model):
    comment = db.StringProperty(required=True)
    post = db.StringProperty(required=True)
    author = db.StringProperty(required=True)

    @classmethod
    def render(self):
        self.render("comment.html")


class UpdateComment(BlogHandler):
    def get(self, post_id, comment_id):
        # Check if user is logged in
        if not self.user:
            return self.redirect("/login")
		
	post = Post.get_by_id(int(post_id), parent=blog_key())
	comment = Comment.get_by_id(int(comment_id), parent=self.user.key())

        if comment:
            return self.render("updatecomment.html",
                               subject=post.subject,
                               content=post.content,
                               comment=comment.comment)
        else:
            return self.redirect('/commenterror')

    def post(self, post_id, comment_id):
        # Check if user is logged in
	if not self.user:
            return self.redirect("/login")
		
		
        comment = Comment.get_by_id(int(comment_id),
                                    parent=self.user.key())
	# Check if User is logged in / or is element created from me
        if not comment:
            return self.redirect("/login")
        
        if comment.parent().key().id() == self.user.key().id():
            comment.comment = self.request.get('comment')
            comment.put()
        return self.redirect('/blog/%s' % str(post_id))


class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        comment = Comment.get_by_id(int(comment_id),
                                    parent=self.user.key())

        # check if comment exists
        if not comment:
            return self.redirect("/login")
        
        author = comment.author
	# Check if User is logged in / or is element created from me
        if not self.user:
            return self.redirect("/login")
        
        loggedUser = self.user.name
        if comment and author == loggedUser:
            comment.delete()
            return self.redirect('/blog/%s' % str(post_id))
        else:
            return self.redirect('/commenterror')


class CommentError(BlogHandler):
    def get(self):
        self.write('Something went wrong.')


class NewComment(BlogHandler):
    def get(self, post_id):
	# Check if User is logged in / or is element created from me
        if not self.user:
            return self.redirect("/login")

        post = Post.get_by_id(int(post_id),
                              parent=blog_key())
        subject = post.subject
        content = post.content
        self.render("newcomment.html",
                    subject=subject,
                    content=content,
                    pkey=post.key())

    def post(self, post_id):
        key = db.Key.from_path('Post',
                               int(post_id),
                               parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
		# Check if User is logged in / or is element created from me
        if not self.user:
            return self.redirect('login')

        comment = self.request.get('comment')

        if comment:
			
            author = self.request.get('author')
            c = Comment(comment=comment,
                        post=post_id,
                        parent=self.user.key(),
                        author=author)
            c.put()
            return self.redirect('/blog/%s' % str(post_id))
        else:
            error = "please provide a comment!"
            return self.render("permalink.html",
                               post=post,
                               content=content,
                               error=error)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True)
    liked_by = db.ListProperty(str)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))


class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created').fetch(10)
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post',
                               int(post_id),
                               parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html",
                    post=post)


class RemovePost(BlogHandler):
    def get(self, post_id):
	# Check if User is logged in / or is element created from me
        if not self.user:
            return self.redirect('/login')
        else:
            key = db.Key.from_path('Post',
                                   int(post_id),
                                   parent=blog_key())
            post = db.get(key)
            author = post.author
            loggedUser = self.user.name
	    # Check if User is logged in / or is element created from me
            if author == loggedUser:
                key = db.Key.from_path('Post',
                                       int(post_id),
                                       parent=blog_key())
                post = db.get(key)
            # Check if that post exists
                if not post:
                    return self.error(404)                    
                
                post.delete()
                self.render("removepost.html")
            else:
                return self.redirect("/")


class LikePost(BlogHandler):
# Check if User is logged in / or is element created from me
    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')
        else:
            key = db.Key.from_path('Post',
                                   int(post_id),
                                   parent=blog_key())
            post = db.get(key)
            # Check if that post exists
            if not post:
                return self.error(404)
            
            author = post.author            
	    # Check if User is logged in / or is element created from me
            logged_user = self.user.name
            if author == logged_user or logged_user in post.liked_by:
                return self.redirect('/error')
            else:
                post.likes += 1
                post.liked_by.append(logged_user)
                post.put()
                return self.redirect("/blog")


class EditPost(BlogHandler):
# Check if User is logged in / have permissions to edit a post
    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')
        else:
            key = db.Key.from_path('Post',
                                   int(post_id),
                                   parent=blog_key())
            post = db.get(key)
            author = post.author
            loggedUser = self.user.name
	    # Check if PostAuthor is loggedIn User (Creator)
            if author == loggedUser:
                key = db.Key.from_path('Post',
                                       int(post_id),
                                       parent=blog_key())
                post = db.get(key)
                 # Check if that post exists
                if not post:
                    return self.error(404)
            
                error = ""
                self.render("edit.html",
                            subject=post.subject,
                            content=post.content,
                            error=error)
            else:
                return self.redirect("/error")

    def post(self, post_id):
	# Check if User is logged in / have permissions to edit a post
        if not self.user:
            return self.redirect("/login")

	key = db.Key.from_path('Post',
                                   int(post_id),
                                   parent=blog_key())
        post = db.get(key)
        # Check if that post exists
        if not post:
                    return self.error(404)
                
        author = post.author
        
	# Check if this post is my post
        loggedUser = self.user.name
        if not author == loggedUser:
            return self.redirect("/login")
        else:
            
            post.subject = self.request.get('subject')
            post.content = self.request.get('content')
            post.put()
            return self.redirect('/blog/%s' % str(post.key().id()))




class NewPost(BlogHandler):
# Check if User is logged in / have permissions to create a post
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.request.get('author')

        if subject and content:
            p = Post(parent=blog_key(),
                     subject=subject,
                     content=content,
                     author=author,
                     likes=0,
                     liked_by=[])
            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Please add a valid subject or content!"
            return self.render("newpost.html",
                               subject=subject,
                               content=content,
                               error=error)


# SignUp Page
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
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

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


# Register Handling
class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html',
                        error_username=msg)
        else:
            u = User.register(self.username,
                              self.password,
                              self.email)
            u.put()

            self.login(u)
            return self.redirect('/blog')


# Login Handling
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html',
                        error=msg)


# Error Handling
class Error(BlogHandler):
    def get(self):
        self.render('error.html')


# Logout Handling
class Logout(BlogHandler):
    def get(self):
        self.logout()
        return self.redirect('/signup')


# Routing
app = webapp2.WSGIApplication([('/?', Home),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)/removepost', RemovePost),
                               ('/signup', Register),
                               ('/blog/([0-9]+)/edit', EditPost),
                               ('/blog/([0-9]+)/like', LikePost),
                               ('/rot13', Rot13),
                               ('/welcome', Welcome),
                               ('/login', Login),
                               ('/error', Error),
                               ('/logout', Logout),
                               ('/blog/([0-9]+)/newcomment', NewComment),
                               ('/blog/([0-9]+)/updatecomment/([0-9]+)',
                                UpdateComment),
                               ('/blog/([0-9]+)/deletecomment/([0-9]+)',
                                DeleteComment),
                               ('/commenterror', CommentError),
                               ],
debug=True)
