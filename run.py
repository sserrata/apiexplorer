#!/usr/bin/env python
import os, sys
from app import app
import gunicorn.app.base
from gunicorn.six import iteritems
import argparse


"""Run Micro-instance of API Explorer

For development, debugging or troubleshooting.

"""


class WebApp(gunicorn.app.base.BaseApplication):

    def init(self, parser, opts, args):
        pass

    def __init__(self, app_, options_=None):
        self.options = options_ or {}
        self.application = app_
        super(WebApp, self).__init__()

    def load_config(self):
        config = dict(
            [
                (key, value) for key, value in iteritems(self.options)
                if key in self.cfg.settings and value is not None
            ]
        )
        for key, value in iteritems(config):
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


if __name__ == '__main__':
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Palo Alto Networks API Explorer\n\n"
    )
    p.add_argument(
        "-d", "--debug", nargs='?', const=True, help="Debug mode"
    )
    a = p.parse_args()
    if a.debug:
        DEBUG = True
    else:
        DEBUG = False

    if DEBUG:
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        app.run(host='127.0.0.1', port=5000, debug=True)
    else:
        options = {
            'bind': '%s:%s' % ('127.0.0.1', '443'),
            'workers': '4',
            'timeout': '300',
            'loglevel': 'info',
            'max_requests': '25',
            'worker_class': 'sync',
            'errorlog': '-',
            'accesslog': '-',
            'certfile': 'app/ssl/cert.pem',
            'keyfile': 'app/ssl/cert.key'
        }
        WebApp(app, options).run()
