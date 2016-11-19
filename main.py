
#main.py created November 18, 2016 by Christine Stoner

__copyright__ = """

    Copyright 2016 Christine Stoner

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

"""
__license__ = "Apache 2.0"


import os
import re
import random
import hashlib
import hmac
from string import letters
import logging

import webapp2
import jinja2

from google.appengine.ext import db

# Establish jinja environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# Set secret
secret = 'sekrjeathwjkg522874295467856087dsj'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Encode val for cookie
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# Check encoding of val from cookie
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Define functions to be used throughout blog
class BlogHandler(webapp2.RequestHandler):

    # Set write function for template
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # Add user to params
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    # Set rendering of template with key word arguments   
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Function to set a cookie securely
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Check for accuracy of cookie information
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Securely set userid in cookie
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Clear secure cookie upon logout.
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Read user from cookie and set
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

# Function to render post in templates
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

# Set functions for main page functionality
class MainPage(BlogHandler):
  def get(self):
        self.redirect('/blog')
    
##### user stuff

# Make a random salt
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

# Hash the password with salt if not yet determined
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# Check for validity of password
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# Return users key from given group
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# Set up model to track users
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    # Return User from id argument
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    # Return user when filtered by name argument
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    # Register user by hashing password and returning user object with
    # Password hash
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    # Check user for valid password
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

##### blog_key -> Post -> Comment

# Return blog key
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

#### post stuff

# Defines Post class ancestor is blog key
# Used to capture blog posts
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    created_by = db.IntegerProperty(required = True)
    users_that_like = db.StringProperty()

    # Renders Post in template for display purposes
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)
    
    # Adds users to string of users that have liked the page.
    def add_like(self, userid):
        likes = self.users_that_like
        if likes:
            slikes = str(likes)
            add_likes = slikes + ',' + str(userid)
            self.users_that_like = add_likes
        else:
            self.users_that_like = str(userid)
        self.put()
        return 

   # Counts users that have liked the page
    def get_likes_count(self):
        if self.users_that_like:
            likes = self.users_that_like.split(',')
            return len(likes)
        else:
            return 0

   # Returns True if user is currently listed as liking the post.
    def has_user_liked(self, userid):
        if self.users_that_like:
            user_likes = self.users_that_like.split(',')
            return str(userid) in user_likes
        else:
            return False

    # Removes user from list of users that like the post
    # if the user is listed as liking the post.
    def add_dislike(self, userid):
        likes = self.users_that_like
        if likes:
            add_dislikes = likes.split(',')
            updated_dislikes = add_dislikes.remove(str(userid))
            if updated_dislikes:
                new_likes = ",".join(updated_dislikes)
                self.users_that_like = new_likes
            else:
                self.users_that_like = None
        self.put()
        return 

    # Returns a count of comments associated with each post.
    def count_comments(self):
        return Comment.all().ancestor(self.key()).count()


#class handing the main/first page display of the blog    
class BlogFront(BlogHandler):
    # Displays posts sorted in reverse order by creation date
    # Ancestor added for strong consistency.
    def get(self):
        userid = -1
        if self.user:
            userid = self.user.key().id()
        posts = Post.all().ancestor(blog_key()).order('-created')
        self.render('front.html', posts = posts, userid = userid, error="")

    # Handles like and dislike functionality by post
    def post(self):
        if self.user:
            userid = self.user.key().id()
            # Checks if like button pushed
            if self.request.get('like'):
                post_id = self.request.get('like')
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                if not post:
                    self.error(404)
                    return
                # Checks if user has liked before
                if post.has_user_liked(userid):
                    error = "Sorry, you have already liked this post."
                    self.render("error.html", error=error)
                    return
                # Checks if users' post
                if userid == post.created_by:
                    error = "Sorry, you cannot like your own post."
                    self.render("error.html", error=error)
                    return
                else:
                    post.add_like(userid)
                    self.redirect('/blog')
                    return
            # Checks if dislike button pushed
            elif self.request.get('dislike'):
                post_id = self.request.get('dislike')
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                if not post:
                    self.error(404)
                    return
                # Checks if user has liked previously
                if post.has_user_liked(userid):
                    post.add_dislike(userid)
                    self.redirect('/blog')
                    return
                else:
                    error = "You must have like this post before to unlike now."
                    self.render("error.html", error=error)
                    return
            else:
                self.redirect('/blog')
                
               
# Class handling the display of each individual post
class PostPage(BlogHandler):
    # Displays each individual post if user is signed in.
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            self.render("permalink.html", post = post)
        else:
            self.redirect('/signup')

# Class handling the editing of existing posts by their creator
class EditPost(BlogHandler):
    # Returns edit post page if user is signed in.
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            postid = post.key().id()

            if not post:
                self.error(404)
                return

            self.render("editpost.html", subject=post.subject,
                         content=post.content, postid=postid)
        else:
            self.redirect('/signup')
    # Updates edited post for changes if edits submitted by 
    # original creator
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
       

        subject = self.request.get('subject')
        content = self.request.get('content')
        userid = self.user.key().id()

        if subject and content:
            if userid == post.created_by:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                error = "you may only edit your own posts"
                self.render("newpost.html", subject=subject, content=content,
                             error=error)
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)

# Class handling deleting of posts by their creator
class DeletePost(BlogHandler):
    # Returns delete page if user is signed in
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            

            if not post:
                self.error(404)
                return

            self.render("deletepost.html", subject=post.subject,
                        content=post.content)
        else:
            self.redirect('/signup')

    # Deletes post if request is submitted by original creator
    def post(self, post_id):

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = Comment.all().ancestor(key)

        if not post:
            self.error(404)
            return
        
        userid = self.user.key().id()

        if userid == post.created_by:
            post.delete()
            for comment in comments:
                comment.delete()
            self.render("delete.html")
        else:
            error = "You may only delete your own posts"
            self.render("deletepost.html", subject=post.subject,
                        content=post.content, error=error)



# Handles adding new posts by logged in users
class NewPost(BlogHandler):
    # Returns new post page to signed in users
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/signup")

    # Updates new posts from signed in users
    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        userid = self.user.key().id()

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, 
                     content = content, created_by=userid)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)

####      Comment stuff

# Defines comments class ancestor is each post
class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add = True)
    created_by = db.IntegerProperty(required=True)
    
    # rendering function for comment
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c = self)

# Handles adding new comments by logged in users
class NewComment(BlogHandler):
    # returns new comment page to logged in users
    def get(self, post_id):
        if self.user:
            self.render("newcomment.html")
        else:
            self.redirect("/login")

    # updates new comments from logged in users
    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        content = self.request.get('content')
        userid = self.user.key().id()

        if content:
            c = Comment(parent = key, content = content, created_by=userid)
            c.put()
            self.redirect('/blog')
        else:
            error = "content, please!"
            self.render("newcomment.html", content=content, error=error)


# Diplays comments for each post 
class ReadComments(BlogHandler):
    # displays comments as available for each post
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        comments = Comment.all().ancestor(key)
        if self.user:
            userid = self.user.key().id()
        else:
            userid = -1

        no_comments = ""

        if comments.count() >0:
            self.render("commentspage.html", postid=post_id, 
                         comments = comments, no_comments=no_comments, 
                         userid=userid)
        else:
            no_comments = "No Comments Found"
            self.render("commentspage.html", postid=post_id, 
                        comments = comments, no_comments=no_comments, 
                        userid=userid)

# Handles editing comments for logged in users
class EditComment(BlogHandler):
    # Returns editing comment page for logged in users
    def get(self, post_id, comment_id):
        if self.user:
            post_key = db.Key.from_path('Post', int(post_id), 
                                        parent=blog_key())
            comment_key = db.Key.from_path('Comment', int(comment_id),
                                           parent=post_key)
            comment = db.get(comment_key)

            if not comment:
                self.error(404)
                return

            self.render("editcomment.html", content=comment.content, 
                         postid=str(post_id), comment=str(comment_id),
                         error="")
        else:
            self.redirect('/signup')

    # processes edits to comments if comment created by logged in user
    def post(self, post_id, comment_id):

        post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        comment_key = db.Key.from_path('Comment', int(comment_id), 
                                       parent=post_key)
        comment = db.get(comment_key)

        if not comment:
            self.error(404)
            return
       
        userid = self.user.key().id()
    
        content = self.request.get('content')
    

        if content:
            if userid == comment.created_by:
                comment.content = content
                comment.put()
                self.redirect('/blog/readcomments/%s' % str(post_id))
            else:
                error = "you may only edit your own comments"
                self.render("editcomment.html", content=content,
                            postid=str(post_id), comment=str(comment_id),
                            error=error)
        else:
            error = "content, please!"
            self.render("editcomment.html", content=content, 
                        postid=str(post_id), comment=str(comment_id),
                        error=error)

# Handles deleting comments for logged in users
class DeleteComment(BlogHandler):
    # Returns delete comment page for logged in users
    def get(self, post_id, comment_id):
        if self.user:
            post_key = db.Key.from_path('Post', int(post_id),
                                        parent=blog_key())
            comment_key = db.Key.from_path('Comment', int(comment_id),
                                           parent=post_key)
            comment = db.get(comment_key)

            if not comment:
                self.error(404)
                return

            self.render("deletecomment.html", content=comment.content, 
                        postid=str(post_id), comment=str(comment_id),
                        error="")
        else:
            self.redirect('/signup')

    # Deletes comment if requested by comment's creator
    def post(self, post_id, comment_id):

        post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        comment_key = db.Key.from_path('Comment', int(comment_id),
                                       parent=post_key)
        comment = db.get(comment_key)

        if not comment:
            self.error(404)
            return
        
        userid = self.user.key().id()

        if userid == comment.created_by:
            comment.delete()
            self.render("delete.html")
        else:
            error = "You may only delete your own comments"
            self.render("deletecomment.html", content=comment.content,
                        postid=str(post_id), comment=str(comment_id),
                        error=error)

####    Sign up Stuff

# Determine validity of user name
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

# Determine validity of password
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

# Determine validity of e-mail
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Handles registration of users
class Signup(BlogHandler):
    # Returns signup form
    def get(self):
        self.render("signup-form.html")
    
    # Checks validity of user and addes to user database
    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
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

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

# Completes registration process
class Register(Signup):
    def done(self):
        # Make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

# Handles logging in of established users
class Login(BlogHandler):
    # Returns log-in form
    def get(self):
        self.render('login-form.html')

    # Logs in valid users, returns error if not valid
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

# Logs out users
class Logout(BlogHandler):
    # Logs out users and redirects to signup page
    def get(self):
        self.logout()
        self.redirect('/signup')

# Provies welcome page for users
class Welcome(BlogHandler):
    def get(self):
        if self.user:
            username = self.user.name
            self.render('welcome.html', username = username)
        else:
            self.redirect('/signup')

# Handles routing
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit/([0-9]+)',EditPost),
                               ('/blog/delete/([0-9]+)',DeletePost),
                               ('/blog/comment/([0-9]+)', NewComment),
                               ('/blog/readcomments/([0-9]+)', ReadComments),
                               ('/blog/([0-9]+)/editcomment/([0-9]+)',
                                 EditComment),
                               ('/blog/([0-9]+)/deletecomment/([0-9]+)',
                                 DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome)
                               ],
                              debug=True)
