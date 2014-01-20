import os
import re
import string
import urllib
import random
import hashlib
import collections
import tornado.ioloop
import tornado.web
import tornado.auth
import tornado.gen
import tornado.httpclient
import PythonMagick
import tempfile
import urllib
import base64
import pycassa

from datetime import datetime

from pycassa.pool import ConnectionPool
from pycassa.columnfamily import ColumnFamily
from pycassa import NotFoundException

pool = ConnectionPool('imgthumb')
usersTable = ColumnFamily(pool, 'Users')
userThumbnailsTable = ColumnFamily(pool, 'UserThumbnails')
thumbnailsTable = ColumnFamily(pool, 'Thumbnails')

staticPath =  os.path.join(os.path.dirname(os.path.realpath(__file__)), 'static')
print('static path: ' + staticPath)

from mako.template import Template
from mako.lookup import TemplateLookup

#from models import *
#setup_all()
#create_all()

#from sqlalchemy.orm.exc import NoResultFound

# returns the user entity based on the user's cookie
def userByEmail(email):
    if not email:
        raise NotFoundException('email is None')
    return usersTable.get(email)
#    print(foo)
#    bar = userPool.get(email + "_x")
#    return User.query.filter_by(email=email).one()

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
        
        email = user['email']
        try:
            userByEmail(email)
        except NotFoundException:
            #            newUser = User()
            #            newUser.email = user['email']

            print('adding new user to table: ' + user['email'])
            usersTable.insert(email, { 'created' : datetime.utcnow().strftime("%Y%m%d") })

            #prodSession.commit()

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

class LogoutHandler(tornado.web.RequestHandler):
    def get(self):
        self.clear_cookie('user')
        self.redirect('/')

class HomeHandler(tornado.web.RequestHandler):
    def get(self):
        baseTemplate = templates.get_template("home.html")
                
        email = self.get_secure_cookie('user')
        if email:
            print(dir(usersTable))

            emailList = list(usersTable.get_range())
            print(emailList)

            print('user logged in, getting their info: ' + email)
            user = userByEmail(self.get_secure_cookie('user'))

#            userThumbnails = UserThumbnail.query.filter_by(user=user)

            #thumbnailInfo = UserThumbnail.query.filter_by(id=user.id).join('thumbnail').all()
            #print(thumbnailInfo)
            #print(dir(thumbnailInfo[0]))

            try:
                userThumbnails = userThumbnailsTable.get(email)

                thumbnails = [] #map(objToData, userThumbnails)
                for urlSha,empty in userThumbnails.iteritems():
                    try:
                        urlSha.decode('ascii') 
                        thumbnails.append({ 'urlSha' : urllib.quote(urlSha),
                                        'url' : urlSha })
                    except UnicodeDecodeError:
                        pass
            except NotFoundException:
                thumbnails = []

#            print(prodMetadata.tables)
#            UserThumbnail.thumbnails.property.secondary
#            UserThumbnail._descriptor.find_relationship('tags').secondary_table

            # should be using smarter joins, need to read the docs on relationships

        else:
            print('assume nothing!')
            thumbnails = []

        self.write(renderWithBaseInfo(self, baseTemplate, thumbnails=thumbnails))

class RecommendationsHandler(tornado.web.RequestHandler):
    def get(self):
        template = templates.get_template("recommendations.html")

        self.write(renderWithBaseInfo(self, template))

class StatusHandler(tornado.web.RequestHandler):
    def get(self):
        if 'THUMB_ADMIN_EMAIL' not in os.environ:
            raise tornado.web.HTTPError(403)
        elif os.environ['THUMB_ADMIN_EMAIL'] != self.get_secure_cookie('user'):
            raise tornado.web.HTTPError(403)
        
        numThumbs = len(list(thumbnailsTable.get_range(column_count=0, filter_empty=False))) #len([a for a in Thumbnail.query.all()])

        statusTemplate = templates.get_template("status.html")
        self.write(statusTemplate.render(numThumbs=numThumbs))

class ThumbnailHandler(tornado.web.RequestHandler):
    def get(self): # return encoded thumbnail
        if not self.get_secure_cookie('user'):
            raise tornado.web.HTTPError(403)

        urlSha = self.get_argument('id', None)

        try:
            encoding = thumbnailsTable.get(urlSha)['encoding']
            data = base64.b64decode(encoding) #, altchars=altChars)

            self.set_header("Content-Type", "image/jpeg")
            self.write(data)
        except NotFoundException:
            raise tornado.web.HTTPError(404)

#        print('requested urlSha: %s' % urlSha)

#        self.write('nope')

class ImageHandler(tornado.web.RequestHandler):
    def get(self): # returns INFO about a thumb
        if not self.get_secure_cookie('user'):
            raise tornado.web.HTTPError(403)

        thumbId = self.get_argument('thumb_id', None)
        print(thumbId)

        if not thumbId:
            raise tornado.web.HTTPError(404)
        
        try:
            self.write(self._thumbInfo(thumbId))
        except NoResultFound:
            raise tornado.web.HTTPError(404)


    @tornado.web.asynchronous
    def post(self):
        if not self.get_secure_cookie('user'):
            raise tornado.web.HTTPError(403)

        url = self.get_argument('url', default=None)
        if not url:
            raise tornado.web.HTTPError(400)

        if not self.get_secure_cookie('user'):
            raise tornado.web.HTTPError(403)

        # TODO: check time of last url, max it out at like five seconds

        # TODO: make sure there aren't any query strings

        # return early if url already encoded
        try:
            thumbnail = thumbnailsTable.get(url) #Thumbnail.query.filter_by(url=url).one()

            email = self.get_secure_cookie('user')
            user = userByEmail(email)
            urlSha = addThumbnailToUser(email, url)

            self._replyPostSuccess(urlSha)
        except NotFoundException:
            print('* querying url: ' + url)

            httpClient = tornado.httpclient.AsyncHTTPClient()
            httpClient.fetch(url,
                             callback=self.onFetch)

    def onFetch(self, response):
        #print('* got response')
        #print(response)
        #print(type(response))
        #print(response.code)
        #print(response.request_time)

        # TODO: check response.code

#        print(response.body)

        # TODO: fail if response too big

        url = response.request.url

        print('fetched url: ' + url)

        tmpFile = tempfile.NamedTemporaryFile(suffix='.jpg')
        tmpFile.write(response.body)

        data = encodeImage(tmpFile.name)

        urlSha = quickSha1(url)
        thumbnailsTable.insert(urlSha, { 'url' : url, 'encoding' : data })
        #thumbnail = Thumbnail()
        #thumbnail.url = url
        #thumbnail.encoding = data        
        #prodSession.commit()

        tmpFile.close()

        email = self.get_secure_cookie('user')
        addThumbnailToUser(email, url)

        print('stored user thumbnail: %s -> %s' % (email, url))
        self._replyPostSuccess(urlSha)

    def _replyPostSuccess(self, urlSha):
        try:
            self.write(self._thumbInfo(urlSha))
        except NoResultFound:
            raise tornado.web.HTTPError(404)
        self.finish()

    def _thumbInfo(self, urlSha):
        thumbnail = thumbnailsTable.get(urlSha)
#        thumbnail = Thumbnail.query.filter_by(id=thumbnailId).one()
        return { 'thumb_id' : urlSha,
                 'url' : thumbnail['url'] }

# takes an image file path and returns the base-64 encoded jpg data
def encodeImage(fileName):
    img = PythonMagick.Image(fileName)
    #print(dir(img))
    #print(img)
    width = img.size().width()
    height = img.size().height()
    print('encoding image: %ix%i' % (width, height))

    # TODO: this should be 32x32 with a border preserving aspect ratio
    img.sample('!32x32')

    # use jpg encoding for everything
    thumbFile = tempfile.NamedTemporaryFile(suffix='.jpg')
    img.write(thumbFile.name)

    thumbFile.seek(0)
    data = thumbFile.read()

    return base64.b64encode(data) #, altchars=altChars)

def addThumbnailToUser(email, url):
#    user = User.query.filter_by(id=userId).one()
#    thumbnail = Thumbnail.query.filter_by(id=userId).one()

    urlSha = quickSha1(url)
    userThumbnailsTable.insert(email, { urlSha : url })

    # TODO: this check probably isn't necessary
    #try:
    #    UserThumbnail.query.filter_by(user=user).filter_by(thumbnail=thumbnail).one()
    #    print('already stored...')
    #except NoResultFound:
    #    userThumbnail = UserThumbnail()
    #    userThumbnail.user = user
    #    userThumbnail.thumbnail = thumbnail
    #    print('mapped thumbnail to user...')

    #    prodSession.commit()

def quickSha1(data):    
    s = hashlib.sha1()
    s.update(data)
    encodedDigest = base64.b64encode(s.digest()) #, altchars=altChars)
    print('quickSha1: ' + encodedDigest)
    return encodedDigest

application = tornado.web.Application([
    (r"/", HomeHandler),
    (r"/g_login", GoogleLoginHandler),
    (r"/create_login", CreateLoginHandler),
    (r"/login", LoginHandler),
    (r"/logout", LogoutHandler),
    (r'/static/(.*)', tornado.web.StaticFileHandler, {'path': staticPath}),
    (r"/status", StatusHandler),
    (r"/recommendations", RecommendationsHandler),
    (r"/image", ImageHandler),
    (r"/thumbnail", ThumbnailHandler),
], cookie_secret=os.environ['GAZETTE_SECRET'])

if __name__ == "__main__":
    port = 8888
    application.listen(port)
    print('serving from http://localhost:%i' % port)
    tornado.ioloop.IOLoop.instance().start()

