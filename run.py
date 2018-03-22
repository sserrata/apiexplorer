#!/usr/bin/env python
import os
from app import app

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    app.run(
        host='0.0.0.0',
        debug=True,
        ssl_context=('app/ssl/apollo11.crt', 'app/ssl/apollo11.key'),
        port=443
    )
