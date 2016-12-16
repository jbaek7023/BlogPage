from google.appengine.ext import db
import random
from string import letters
import hashlib

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        user = User.all().filter('name =', name).get()
        return user

    @classmethod
    def register(cls, username, password, email):
        pw_hash = make_pw_hash(username, password)
        return User(
            name=username,
            pw_hash=pw_hash,
            email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)

        if u and valid_pw(name, pw, u.pw_hash):
            return u


# user stuff
def make_salt():
    return ''.join(random.choice(letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name+pw+salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)