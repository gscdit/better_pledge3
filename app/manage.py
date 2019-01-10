# from views import app
from flask import Flask
from flask_apidoc import ApiDoc
from flask_apidoc.commands import GenerateApiDoc
from flask_script import Manager
app = Flask(__name__)
doc = ApiDoc(app=app)


manager = Manager(app)
manager.add_command('apidoc', GenerateApiDoc())

if __name__ == "__main__":
    manager.run()
