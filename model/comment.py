from google.appengine.ext import db

class Comment(db.Model):
    comment = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    made_by = db.StringProperty(required=True)
    created_in = db.DateTimeProperty(auto_now=True)