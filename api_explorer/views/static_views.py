import os

from flask import Blueprint, send_from_directory, current_app

static_views = Blueprint('static_views', __name__)


@static_views.route('/img/<path:path>')
def send_img(path):
    return send_from_directory(os.path.join(current_app.root_path, 'static/img'), path)


@static_views.route('/css/<path:path>')
def css(path):
    return send_from_directory(os.path.join(current_app.root_path, 'static/css'), path)


@static_views.route('/js/<path:path>')
def js(path):
    return send_from_directory(os.path.join(current_app.root_path, 'static/js'), path)


@static_views.route('/fonts/<path:path>')
def fonts(path):
    return send_from_directory(os.path.join(current_app.root_path, 'static/css/fonts'), path)
