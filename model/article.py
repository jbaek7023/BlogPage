from google.appengine.ext import db
from comment import Comment

class Article(db.Model):
    title = db.StringProperty(required=True)
    date = db.DateTimeProperty(auto_now_add=True)
    text = db.TextProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(required=True)
    who_liked = db.ListProperty(str)
    created_by = db.TextProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("main.html", article=self)

    @classmethod
    def by_id(self, post_id):
        key = db.Key.from_path('Article', int(post_id))
        article = db.get(key)
        return article

    @property
    def comments(self):
        return Comment.all().filter("post_id = ", str(self.key().id()))