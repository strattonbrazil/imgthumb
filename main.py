import os
import re
import string
import urllib
import random
import collections
from pytz import timezone
import pytz
import tornado.ioloop
import tornado.web
import tornado.auth
import tornado.gen
import tornado.httpclient
import PythonMagick

staticPath =  os.path.join(os.path.dirname(os.path.realpath(__file__)), 'static')
print('static path: ' + staticPath)

from mako.template import Template
from mako.lookup import TemplateLookup

from models import *
setup_all()
create_all()

from sqlalchemy.orm.exc import NoResultFound

# returns the user entity based on the user's cookie
def userByEmail(email):
    return User.query.filter_by(email=email).one()

templates = TemplateLookup(directories=['./templates'])

def renderWithBaseInfo(handler, template, **kwargs):
    email = handler.get_secure_cookie('user')
    loggedIn = email and len(email) > 0
    if 'redirect_uri' not in kwargs:
        kwargs['redirect_uri'] = '/'
    return template.render(loggedIn=loggedIn, **kwargs)

class GoogleLoginHandler(tornado.web.RequestHandler, tornado.auth.GoogleMixin):
    @tornado.web.asynchronous
    def get(self):
        if self.get_argument("openid.mode", None):
            self.get_authenticated_user(self.async_callback(self._on_auth))
            return
        self.authenticate_redirect()
  
    def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, "Google auth failed")
        self.set_secure_cookie('user', user['email'])
        
        try:
            userByEmail(user['email'])
        except NoResultFound:
            newUser = User()
            newUser.email = user['email']

            prodSession.commit()

        redirectUri = self.get_argument('redirect_to', default=None)
        if redirectUri:
            print('redirecting from login auth: %s' % redirectUri)
            self.redirect(redirectUri)
        else:
            self.redirect('/')

        #self.finish()

class LoginHandler(tornado.web.RequestHandler):
    def get(self):
        loginTemplate = templates.get_template("login.html")

        # TODO: should take you back to original page
        uri = urllib.quote('/')

        self.write(loginTemplate.render(redirect_uri=uri))
          
class CreateLoginHandler(tornado.web.RequestHandler):
    def get(self):
        loginTemplate = templates.get_template("login.html")

        uri = urllib.quote('/create')
        
        self.write(loginTemplate.render(redirect_uri=uri))

class CreateHandler(tornado.web.RequestHandler):
#    @tornado.web.asynchronous
    def get(self):
        articleId = self.get_argument('article_id', default=None)
        if not self.get_secure_cookie('user'):
            print('user not stored, redirecting to login')
            self.redirect('/create_login')
        else:
            addAuthors()

            title = ''
            markdown = ''
            category = 'opinion'

            authors = map(lambda author: { 'name' : author.name, 'id' : author.id },
                          Author.query.all())

            if articleId:
                article = Article.query.filter_by(id=articleId).one()
                title = article.title
                markdown = article.markdown
                authorId = article.author.id
                category = article.category
            else:
                authorId = random.choice(authors)['id'] # assign random author

            createTemplate = templates.get_template("create.html")
            self.write(renderWithBaseInfo(self, createTemplate, 
                                          title=title, 
                                          markdown=markdown, 
                                          articleId=articleId, 
                                          authorId=authorId,
                                          category=category,
                                          categories=articleCategories,
                                          authors=authors))

    def post(self):
        if not self.get_secure_cookie('user'):
            self.set_status(401)
            self.set_header('WWW-Authenticate', 'Basic realm=Users')
        else: # add to database
            title = self.get_argument('title', 'defaultTitle')
            markdown = self.get_argument('markdown', 'defaultMarkdown')
            authorId = int(self.get_argument('author_id', None))
            category = self.get_argument('category', defaultCategory())
            
            

            if category not in articleCategories:
                category = defaultCategory()
                print('defaulting to default category: %s' + category)

            # find author or assign a random one
            authors = Author.query.all()
            authorIds = map(lambda author: author.id, authors)
            if authorId not in authorIds: # assign a random author
                authorId = random.choice(authorIds)
            author = Author.query.filter_by(id=authorId).one()

            def writeRedirect(title, articleId):
                self.write({ 'redirectUri' : articleToLink(category, 
                                                           articleId, 
                                                           title) })

            articleId = self.get_argument('article_id', None)
            if articleId: # existing article
                try:
                    article = Article.query.filter_by(id=articleId).one()
                except NoResultFound:
                    raise tornado.web.HTTPError(404)

                # make sure is owned by current user, else 404
                if article.owner != userByEmail(self.get_secure_cookie('user')):
                    raise tornado.web.HTTPError(403)

                article.title = title
                article.markdown = markdown
                article.author = author
                article.category = category

                prodSession.commit()
                writeRedirect(title, article.id)
            else:
                # TODO: make sure user hasn't created more than a certain amount per hour

                user = userByEmail(self.get_secure_cookie('user'))

                article = Article()
                article.title = title
                article.markdown = markdown
                article.created = datetime.now()
                article.owner = user
                article.published = False
                article.author = author
                article.category = category

                prodSession.commit()
                writeRedirect(title, article.id)

class LogoutHandler(tornado.web.RequestHandler):
    def get(self):
        self.clear_cookie('user')
        self.redirect('/')

class HomeHandler(tornado.web.RequestHandler):
    def get(self):
        baseTemplate = templates.get_template("home.html")

        self.write(renderWithBaseInfo(self, baseTemplate))

class RecommendationsHandler(tornado.web.RequestHandler):
    def get(self):
        template = templates.get_template("recommendations.html")

        self.write(renderWithBaseInfo(self, template))

class StatusHandler(tornado.web.RequestHandler):
    def get(self):
        if 'GAZETTE_ADMIN_EMAIL' not in os.environ:
            raise tornado.web.HTTPError(403)
        elif os.environ['GAZETTE_ADMIN_EMAIL'] != self.get_secure_cookie('user'):
            raise tornado.web.HTTPError(403)
        
        # TODO: this is a stupid way to count, must be better way
        numArticles = len([a for a in Article.query.all()])
        categories = collections.defaultdict(int)
        for a in Article.query.all():
            categories[a.category] += 1
            

        statusTemplate = templates.get_template("status.html")
        self.write(statusTemplate.render(numArticles=numArticles, categories=categories))

class ImageHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def post(self):
        url = self.get_argument('url', default=None)
        if not url:
            raise tornado.web.HTTPError(400)

        if not self.get_secure_cookie('user'):
            raise tornado.web.HTTPError(403)

        # TODO: check time of last url, max it out at like five seconds

        print('* querying url: ' + url)

        httpClient = tornado.httpclient.AsyncHTTPClient()
        httpClient.fetch(url,
                         callback=self.onFetch)

    def onFetch(self, response):
        print('* got response')
        print(response)
        print(type(response))
        print(response.code)
        print(response.request_time)

        # TODO: check response.code

#        print(response.body)

        # TODO: fail if response too big

        tmpFile = open('/tmp/foo.jpg', 'w') #tempfile.NamedTemporaryFile()
        tmpFile.write(response.body)

        encodeImage(tmpFile.name)

        tmpFile.close()

#        tmpFile.close()
        

        # shrink it to 32x32

        self.write('okay')

def encodeImage(fileName):
        img = PythonMagick.Image(fileName)
        print(dir(img))
        print(img)
        print(img.size().width())
        print(img.size().height())

        # TODO: this should be 32x32 with a border
        img.sample('!32x32')

        img.write('/tmp/bar.jpg')




application = tornado.web.Application([
    (r"/", HomeHandler),
    (r"/g_login", GoogleLoginHandler),
    (r"/create_login", CreateLoginHandler),
    (r"/create", CreateHandler),
    (r"/login", LoginHandler),
    (r"/logout", LogoutHandler),
    (r'/static/(.*)', tornado.web.StaticFileHandler, {'path': staticPath}),
    (r"/status", StatusHandler),
    (r"/recommendations", RecommendationsHandler),
    (r"/image", ImageHandler),
], cookie_secret=os.environ['GAZETTE_SECRET'])

if __name__ == "__main__":
    port = 8888
    application.listen(port)
    print('serving from http://localhost:%i' % port)
    tornado.ioloop.IOLoop.instance().start()

