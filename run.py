#!/usr/bin/env python
import os
import gunicorn.app.base
from gunicorn.six import iteritems
import argparse
import ssl
from multiprocessing import cpu_count

from api_explorer.main import create_app

"""Run Micro-instance of API Explorer

For development, debugging or troubleshooting.

"""


def max_workers():
    return cpu_count() * 2 + 1


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
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Palo Alto Networks API Explorer\n\n"
    )
    parser.add_argument(
        "-d", "--debug", action='store_true', default=False, help="Debug mode"
    )
    args = parser.parse_args()

    app = create_app()

    if args.debug:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        if os.path.exists(
            '/etc/ssl/certs/apiexplorer.key'
        ) and os.path.exists('/etc/ssl/certs/apiexplorer.crt'):
            context.load_cert_chain(
                '/etc/ssl/certs/apiexplorer.crt',
                '/etc/ssl/certs/apiexplorer.key'
            )
        elif os.path.exists(
            'ssl/cert.key'
        ) and os.path.exists('ssl/cert.pem'):
            context.load_cert_chain(
                'ssl/cert.key',
                'ssl/cert.pem'
            )
        else:
            context = 'adhoc'
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        app.run(
            host='0.0.0.0', port=443, debug=args.debug, ssl_context=context,
            threaded=True
        )
    else:
        options = {
            'bind': 'unix:/opt/apiexplorer/gunicorn.sock',
            'umask': '0',
            'workers': '%s' % max_workers(),
            'timeout': '300',
            'loglevel': 'info',
            'max_requests': '50',
            'worker_class': 'sync',
            'errorlog': '/var/log/gunicorn/error.log',
            'accesslog': '/var/log/gunicorn/access.log',
        }
        WebApp(app, options).run()
