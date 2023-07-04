from flask import Flask
from flask_pymongo import PyMongo
import mongoengine

mongo2=PyMongo()

def create_app():
    app=Flask(__name__)
    app.config['SECRET_KEY']='jhbfdhbvsovwojenfo'
    app.config['MONGO_URI'] = 'mongodb+srv://adithya:adithya@cluster0.ugn3raa.mongodb.net/test'

    mongoengine.connect(host=app.config['MONGO_URI'])

    mongo2.init_app(app)

    
    from .auth import auth


    app.register_blueprint(auth,url_prefix='/')

    from flask.json import JSONEncoder
    from bson.objectid import ObjectId

    class CustomJSONEncoder(JSONEncoder):
        def default(self, obj):
            if isinstance(obj, ObjectId):
                return str(obj)
            return super().default(obj)
    
    app.json_encoder = CustomJSONEncoder

    return app

