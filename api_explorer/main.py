import sys, os

import click
from flask import Flask, logging, session, request
import logging as logging_
from . import __version__

from api_explorer.constants import VENDOR, DB_DIR_PATH
from api_explorer.extensions import db, security, user_datastore
from api_explorer.oauth_db import OAuthDB
from api_explorer.views.it_views import it_views
from api_explorer.views.static_views import static_views
from api_explorer.views.views import views


def register_blueprints(app):
    app.register_blueprint(static_views)
    app.register_blueprint(views)
    app.register_blueprint(it_views)


def setup_configuration(app):
    app.jinja_env.cache = {}
    app.config['SECRET_KEY'] = '8Q@U99a3wd8NGuY*nRTJ#WAk4r'
    app.config['PERMANENT_SESSION_LIFETIME'] = 1200
    app.config['SECURITY_REGISTERABLE'] = os.environ['SECURITY_REGISTERABLE'] or False
    app.config['SECURITY_TRACKABLE'] = True
    app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
    app.config['SECURITY_CHANGEABLE'] = True
    app.config['SECURITY_SEND_PASSWORD_CHANGE_EMAIL'] = False
    app.config['USE_SESSION_FOR_NEXT'] = True
    app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
    SALT = 'gnEH#S8mbR^mZ46Seu^X^b^^dk'
    app.config['SECURITY_PASSWORD_SALT'] = SALT
    app.jinja_env.cache = {}
    app.jinja_env.lstrip_blocks = True
    app.jinja_env.trim_blocks = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['WTF_CSRF_ENABLED'] = False

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}/security.db'.format(DB_DIR_PATH)


def setup_logging(app):
    log = logging_.getLogger('requests_oauthlib')
    log.addHandler(logging_.StreamHandler(sys.stdout))
    log.setLevel(logging_.DEBUG)
    if __name__ != 'api_explorer.main':
        gunicorn_logger = logging.getLogger('gunicorn.error')
        app.logger.handlers = gunicorn_logger.handlers
        app.logger.handlers = log.handlers
        app.logger.setLevel(gunicorn_logger.level)


def init_extensions(app):
    db.init_app(app)
    # security_ctx has to returned to initiate the security decorators as mentioned here
    # https://github.com/mattupstate/flask-security/issues/340#issuecomment-278560428
    security_ctx = security.init_app(app=app, datastore=user_datastore)
    return security_ctx


def setup_flask_decorators(app, security_ctx):
    with app.app_context():
        @app.context_processor
        def get_global_variables():
            def get_procs():
                import psutil
                master = ['nginx']
                processes = []
                for p in psutil.process_iter():
                    if p.name() in master:
                        processes.append(p.name())
                return processes

            db_ = OAuthDB()
            client = db_.get_activation()
            settings_ = db_.get_settings()
            vendor = settings_.get('vendor', VENDOR)
            try:
                if client.get('activated', False):
                    activated = True
                else:
                    activated = False
            except AttributeError:
                activated = False
            try:
                nginx = get_procs()
            except Exception:
                nginx = []
            return dict(
                activated=activated, nginx=nginx, vendor=vendor,
                version=__version__
            )

        @security_ctx.login_context_processor
        def login_register_processor():
            if not session.get('instance_id', None):
                x = request.args.to_dict()
                params = x.get('params', None)
                if params:
                    import base64
                    try:
                        from urllib.parse import parse_qsl
                    except ImportError:
                        from urlparse import parse_qsl
                    params = base64.b64decode(params)
                    x = dict(parse_qsl(params))
                    parsed_params = {
                        k.decode("utf-8"): v.decode("utf-8") for k, v in x.items()
                    }
                    instance_id = parsed_params.get('instance_id', '')
                    region = parsed_params.get('region', '')
                    session['instance_id'] = instance_id
                    session['region'] = region
                else:
                    session['instance_id'] = ''
                    session['region'] = ''
            return dict()


def create_db(app):
    with app.app_context():
        # Create all the tables that does not exist
        db.create_all()

        # Create the admin user
        if not user_datastore.get_user('admin'):
            user_datastore.create_user(email='admin', password='paloalto')
            db.session.commit()


def create_app():
    app = Flask(__name__)
    register_blueprints(app)
    setup_configuration(app)
    setup_logging(app)
    security_ctx = init_extensions(app)
    create_db(app)
    setup_flask_decorators(app, security_ctx)
    return app


@click.command()
@click.option("--host", default="0.0.0.0", help="Specify the host to bing the app to.")
@click.option("--port", default=None, help="Specify the port to bing the app to.")
@click.option("--debug", is_flag=True, help="Run the Flask app in debug mode")
@click.option("--threaded", is_flag=True, default=True, help="Run the Flask app in threaded mode")
def runserver(host, port, debug, threaded):
    """
    Run the flask app for local development.

    It is recommended to bind the local 443 port to the port you are choosing to run the app with.

    OSX example:

        echo "rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port 5000" | sudo pfctl -ef -
    """
    app = create_app()
    app.run(
        host=host,
        port=port,
        debug=debug,
        ssl_context='adhoc',
        threaded=threaded,
    )


if __name__ == '__main__':
    runserver()
