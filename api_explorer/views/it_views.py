"""
Views to manage, update and restart the webservice process on the docker machine.
"""
import os

from flask import Blueprint, render_template, request
from flask_login import login_required

import requests
import zipfile
import shutil
import subprocess
import pwd

it_views = Blueprint('it_views', __name__)


@it_views.route('/update', methods=['GET'])
@login_required
def update():
    old = '/opt/apiexplorer.old'
    current = '/opt/apiexplorer'
    master = '/opt/apiexplorer-master'
    zip_url = 'https://github.com/PaloAltoNetworks/apiexplorer/archive/master.zip'
    try:
        r = requests.get(zip_url, stream=True)
        with open("/tmp/apiexplorer.zip", "wb") as f:
            f.write(r.content)
    except Exception as e:
        return render_template(
            'pages/updates.html',
            msg="{}".format(e),
            status="danger"
        )
    else:
        try:
            shutil.move(current, old)
            zip_ref = zipfile.ZipFile('/tmp/apiexplorer.zip', 'r')
            zip_ref.extractall('/opt')
            zip_ref.close()
            shutil.move(master, current)
            os.remove('/tmp/apiexplorer.zip')
            shutil.rmtree(old, ignore_errors=True)

            user = pwd.getpwuid(os.geteuid()).pw_name
            subprocess.call(
                ["/usr/bin/chown", "-R", "{user}:{user}".format(user=user), current], shell=False
            )
            subprocess.call(
                ["/usr/bin/sed", "-i", "-e",
                 "1,/\/opt\/apiexplorer\/app/ s/\/opt\/apiexplorer\/app/\/opt\/apiexplorerdb/",
                 "/opt/apiexplorer/api_explorer/constants.py"]
            )
            try:
                os.remove('/opt/apiexplorer/api_explorer/constants.py-e')
            except FileNotFoundError:
                pass
            subprocess.call(
                ["/usr/bin/sudo", "/usr/sbin/service", "gunicorn", "restart"], shell=False
            )
            return render_template(
                'pages/updates.html',
                msg="Success",
                status="success"
            )
        except Exception as e:
            return render_template(
                'pages/updates.html',
                msg="{}".format(e),
                status="danger"
            )


@it_views.route('/restart_process')
@login_required
def restart_process():
    try:
        if 'pname' in request.args:
            pname = request.args['pname']
            include_list = ['gunicorn']
            if pname in include_list:
                subprocess.call(
                    ["/usr/bin/sudo", "/usr/sbin/service", "{}".format(pname), "restart"], shell=False
                )
    except Exception as e:
        return render_template(
            'pages/updates.html',
            msg="{}".format(e),
            status="danger"
        )
    else:
        return render_template(
            'pages/updates.html',
            msg="Success",
            status="success"
        )
