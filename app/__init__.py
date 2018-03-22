from flask import Flask, send_from_directory
import os

app = Flask(__name__, static_url_path='')


@app.route('/adminlte_components/<path:path>')
def send_adminlte(path):
    return send_from_directory(os.path.join(app.root_path, 'vendor/adminlte_components'), path)


@app.route('/adminlte_24/<path:path>')
def send_adminlte_24(path):
    return send_from_directory(os.path.join(app.root_path, 'vendor/adminlte_components_24'), path)


@app.route('/dist/<path:path>')
def send_dist(path):
    return send_from_directory(os.path.join(app.root_path, 'vendor/dist'), path)


@app.route('/img/<path:path>')
def send_img(path):
    return send_from_directory(os.path.join(app.root_path, 'vendor/img'), path)


@app.route('/bower_components/<path:path>')
def send_bootstrap(path):
    return send_from_directory(os.path.join(app.root_path, 'vendor/bower_components'), path)

from app import views
