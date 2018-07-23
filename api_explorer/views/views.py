import json
import uuid
import os

from flask import render_template, request, redirect, session, \
    jsonify, Blueprint, send_from_directory
from flask_security import login_required, auth_required, \
    current_user, logout_user
from pancloud import EventService, LoggingService, \
    DirectorySyncService, Credentials
from pancloud.exceptions import PartialCredentialsError

from api_explorer.constants import APIGW_URL, VENDOR, CSP, AUTHORIZATION_BASE_URL, TOKEN_URL, REVOKE_TOKEN_URL
from api_explorer.app_db import AppDB

views = Blueprint('views', __name__)
db = AppDB()

# Fall back to app.json if credentials.json doesn't exist
try:
    s = db.get_settings()
    c = Credentials(
        token_url=s.get('token_url', TOKEN_URL),
        token_revoke_url=s.get('revoke_token_url', REVOKE_TOKEN_URL),
        auth_base_url=s.get('auth_base_url', AUTHORIZATION_BASE_URL)
    )
    c.refresh()
except PartialCredentialsError:
    s = db.get_settings()
    a = db.get_activation()
    c = Credentials(
        client_id=a.get('client_id', ''),
        client_secret=a.get('client_secret', ''),
        refresh_token=a.get('refresh_token', ''),
        token_url=s.get('token_url', TOKEN_URL),
        token_revoke_url=s.get('revoke_token_url', REVOKE_TOKEN_URL),
        auth_base_url=s.get('auth_base_url', AUTHORIZATION_BASE_URL)
    )
    c.write_credentials()


@views.route('/')
@views.route('/index.html')
@login_required
def index():
    activation = db.get_activation() or {}
    if not session.get('instance_id', None) and not activation.get('instance_id', None):
        logout_user()
        return redirect(CSP)
    return render_template('pages/index.html')


@views.route('/authorization')
@login_required
def authorization():
    activation = db.get_activation() or {}
    s_ = db.get_settings()
    c_ = Credentials(
        token_url=s_.get('token_url', TOKEN_URL),
        token_revoke_url=s_.get('revoke_token_url', REVOKE_TOKEN_URL),
        auth_base_url=s_.get('auth_base_url', AUTHORIZATION_BASE_URL)
    )
    return render_template(
        'pages/authorization.html',
        activation=activation,
        credentials=c_.get_credentials(),
        alert=None,
        msg=None
    )


@views.route('/refresh_tokens')
@auth_required('basic', 'session', 'token')
def refresh_tokens():
    activation = db.get_activation()
    s_ = db.get_settings()
    c_ = Credentials(
        token_url=s_.get('token_url', TOKEN_URL),
        token_revoke_url=s_.get('revoke_token_url', REVOKE_TOKEN_URL),
        auth_base_url=s_.get('auth_base_url', AUTHORIZATION_BASE_URL)
    )
    try:
        token = c_.refresh(timeout=10)
    except Exception as e:
        print(e)
        return render_template(
            'pages/authorization.html',
            credentials=c_.get_credentials(),
            activation=activation,
            alert="danger",
            msg="{}".format(e)
        )
    else:
        c_.write_credentials()
        session['oauth_token'] = {'access_token': token}
        if request.args.get('v', default='html') == 'json':
            return jsonify(token)
        return render_template(
            'pages/authorization.html',
            credentials=c_.get_credentials(),
            activation=activation,
            alert="success",
            msg="SUCCESS"
        )


@views.route('/revoke_refresh_token')
@login_required
def revoke_refresh_token():
    activation = db.get_activation() or {}
    s_ = db.get_settings()
    c_ = Credentials(
        token_url=s_.get('token_url', TOKEN_URL),
        token_revoke_url=s_.get('revoke_token_url', REVOKE_TOKEN_URL),
        auth_base_url=s_.get('auth_base_url', AUTHORIZATION_BASE_URL)
    )
    try:
        c_.revoke_refresh_token(timeout=10)
    except Exception as _e:
        print(_e)
        return render_template(
            'pages/authorization.html',
            activation=activation,
            credentials=c_.get_credentials(),
            alert="danger",
            msg="{}".format(_e)
        )
    else:
        return render_template(
            'pages/authorization.html',
            activation=activation,
            credentials=c_.get_credentials(),
            alert="success",
            msg="SUCCESS"
        )


@views.route('/delete_tokens')
@login_required
def delete_tokens():
    c.remove_profile('default')
    db.delete_activation()
    activation = db.get_activation() or {}
    return render_template(
        'pages/authorization.html',
        credentials=c.get_credentials(),
        activation=activation,
        alert="success",
        msg="SUCCESS"
    )


@views.route("/idp", methods=['POST', 'GET'])
@login_required
def idp():
    """Authorize user."""
    activation = db.get_activation()
    form = request.form
    client_id = form.get('client_id', '')
    client_secret = form.get('client_secret', '')

    s_ = db.get_settings()
    c_ = Credentials(
        token_url=s_.get('token_url', TOKEN_URL),
        token_revoke_url=s_.get('revoke_token_url', REVOKE_TOKEN_URL),
        auth_base_url=s_.get('auth_base_url', AUTHORIZATION_BASE_URL)
    )

    # update credentials
    c_.client_id_ = client_id
    c_.client_secret_ = client_secret
    c_.write_credentials()

    redirect_uri = form.get('redirect_uri', None) or activation.get('redirect_uri', '')
    instance_id = session.get('instance_id', None) or activation.get('instance_id', '')
    region = session.get('region', None) or activation.get('region', '')
    try:
        scope = ' '.join(form.getlist('scope')) or activation.get('scope', '')
    except (KeyError, ValueError):
        scope = ''
    activation_fields = {
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'instance_id': instance_id,
        'region': region,
        'scope': scope
    }
    db.update_activation(activation_fields)
    activation = db.get_activation()
    state = str(uuid.uuid4())
    authorization_url, state = c_.get_authorization_url(
        instance_id=activation.get('instance_id', ''),
        region=activation.get('region', ''),
        redirect_uri=activation.get('redirect_uri', ''),
        state=str(state),
        scope=scope
    )
    session['oauth_state'] = str(state)
    return redirect(authorization_url)


@views.route("/auth-callback", methods=['POST', 'GET'])
def callback():
    """Retrieve an access token."""
    activation = db.get_activation()
    code = request.args.get('code', None)
    state = request.args.get('state', None)
    error = request.args.get('error', None)
    error_description = request.args.get('error_description', '')
    oauth_state = session.get('oauth_state', '')

    s_ = db.get_settings()
    c_ = Credentials(
        token_url=s_.get('token_url', TOKEN_URL),
        token_revoke_url=s_.get('revoke_token_url', REVOKE_TOKEN_URL),
        auth_base_url=s_.get('auth_base_url', AUTHORIZATION_BASE_URL)
    )
    try:
        if oauth_state == state:
            try:
                c_.fetch_tokens(
                    code=code,
                    redirect_uri=activation.get('redirect_uri', ''),
                    client_id=activation.get('client_id', ''),
                    client_secret=activation.get('client_secret', '')
                )
            except Exception as e:
                print('Exception occurred: {}'.format(e))
                print(error)
                db.delete_activation()
                if error:
                    return render_template(
                        'pages/authorization.html',
                        credentials=c_.get_credentials(),
                        activation={},
                        alert="danger",
                        msg="{}: {}".format(error, error_description)
                    )
                else:
                    return render_template(
                        'pages/authorization.html',
                        credentials=c_.get_credentials(),
                        activation={},
                        alert="danger",
                        msg="{}".format(e)
                    )
            else:
                activation = db.get_activation()
                activation.update({'activated': True})
                activation.update({'refresh_token': c_.refresh_token})
                db.update_activation(activation)
                return redirect('/authorization')
        return render_template(
            'pages/authorization.html',
            activation=activation,
            credentials=c_.get_credentials(),
            alert="danger",
            msg="STATE MISMATCH: Possible CSRF detected!"
        )
    except Exception as e:
        return render_template(
            'pages/authorization.html',
            activation=activation,
            credentials=c_.get_credentials(),
            alert="danger",
            msg="{}".format(e)
        )


@views.route('/queryexplorer', methods=['POST', 'GET'])
@login_required
def queryexplorer():
    settings_ = db.get_settings()
    c_ = Credentials(
        token_url=settings_.get('token_url', TOKEN_URL),
        token_revoke_url=settings_.get('revoke_token_url', REVOKE_TOKEN_URL),
        auth_base_url=settings_.get('auth_base_url', AUTHORIZATION_BASE_URL)
    )
    import datetime
    import time
    try:
        from_ = request.form['from']
        if len(from_) > 0 and from_ != 'None':
            from_ = datetime.datetime.fromtimestamp(int(from_)).replace(
                microsecond=0).timestamp()
        else:
            from_ = (datetime.datetime.utcnow() - datetime.timedelta(
                minutes=15)).replace(microsecond=0).timestamp()
    except (KeyError, ValueError):
        from_ = None

    try:
        to_ = request.form['to']
        if len(to_) > 0 and to_ != 'None':
            to_ = datetime.datetime.fromtimestamp(int(to_)).replace(
                microsecond=0).timestamp()
        else:
            to_ = datetime.datetime.utcnow().replace(
                microsecond=0).timestamp()
    except (KeyError, ValueError):
        to_ = None

    try:
        query_ = request.form['query']
        if len(query_) > 0:
            query_ = query_
        else:
            query_ = 'select * from panw.traffic'
    except (KeyError, ValueError):
        query_ = 'select * from panw.traffic limit 100'

    starttime = from_
    endtime = to_

    response = []
    s = ""
    start = time.time()
    if starttime and endtime:
        try:
            ls = LoggingService(
                url=settings_.get('apigw_url', APIGW_URL),
                verify=False,
                credentials=c_
            )
            data = {
                "query": "{}".format(query_),
                "startTime": int(starttime),
                "endTime": int(endtime),
                "maxWaitTime": 0
            }
            q = ls.query(data, timeout=15)
            if 'error' not in q.text:
                try:
                    query_id = q.json()['queryId']
                    data = {
                        "maxWaitTime": 10000
                    }
                    for page in ls.iter_poll(query_id, 0, params=data, timeout=15):
                        print(page.text)
                        try:
                            print(
                                "{}: queryId: {}, sequenceNo: {}, retrieving from {},"
                                " size: {}, took: {} ms\nresult: {}\n".format(
                                    page.json()['queryStatus'],
                                    page.json()['queryId'],
                                    page.json()['sequenceNo'],
                                    page.json()['result']['esResult']['from'],
                                    page.json()['result']['esResult']['size'],
                                    page.json()['result']['esResult']['took'],
                                    page.json()
                                )
                            )
                            response.append(page.json())
                        except Exception:
                            print(
                                "{}: queryId: {}, sequenceNo: {}".format(
                                    page.json()['queryStatus'],
                                    page.json()['queryId'],
                                    page.json()['sequenceNo']
                                )
                            )
                    ls.delete(query_id)
                except Exception as e:
                    print(e)
                    s = q.status_code
                    response = q.text
            else:
                s = q.status_code
                response = q.text
        except Exception as e:
            return render_template(
                'pages/queryexplorer.html', response=str(e),
                sd=starttime,
                ed=endtime, et=time.time() - start,
                headers=[], tabular=False,
                json=None, status=500
            )
    et = time.time() - start
    headers = []
    try:
        m1 = []
        for chunk in response:
            logs1 = chunk['result']['esResult']['hits']['hits']
            max_headers = max(logs1, key=len)
            m1.append(max_headers)
        mh1 = max(m1, key=len)
        for key, _ in mh1['_source'].items():
            headers.append(key)
    except (KeyError, IndexError, ValueError, TypeError):
        try:
            m2 = []
            for chunk in response:
                logs2 = chunk['result']['esResult']['response']['result']['hits']['hits']
                max_headers = max(logs2, key=len)
                m2.append(max_headers)
            mh2 = max(m2, key=len)
            for key, _ in mh2['_source'].items():
                headers.append(key)
        except (KeyError, IndexError, ValueError, TypeError):
            try:
                for chunk in response:
                    logs3 = chunk['result']['esResult']['response']['result']['aggregations']
                    fk = next(iter(logs3))
                    buckets = logs3[fk]['buckets']
                    fb = next(iter(buckets))
                    try:
                        apps = fb['app']['buckets']
                        fa = next(iter(apps))
                        keys = fa.keys()
                    except KeyError:
                        keys = fb.keys()
                    for k in keys:
                        headers.append(k)
            except Exception as e:
                print(e)
                tabular = False
                pass
            else:
                tabular = True
        else:
            tabular = True
    else:
        tabular = True
    try:
        json_response = json.dumps(response)
    except Exception as e:
        print(e)
        json_response = {}
    return render_template(
        'pages/queryexplorer.html', response=response, sd=starttime,
        ed=endtime, et=et, headers=headers, tabular=tabular,
        json=json_response, status=s
    )


@views.route('/logwriter', methods=['POST', 'GET'])
@login_required
def logwriter():
    vendor_id = request.form.get('vendor_id', None)
    log_type = request.form.get('log_type', None)
    payload = request.form.get('json', None)
    settings_ = db.get_settings()
    c_ = Credentials(
        token_url=settings_.get('token_url', TOKEN_URL),
        token_revoke_url=settings_.get('revoke_token_url', REVOKE_TOKEN_URL),
        auth_base_url=settings_.get('auth_base_url', AUTHORIZATION_BASE_URL)
    )
    if vendor_id and log_type and payload:
        try:
            ls = LoggingService(
                url=settings_.get('apigw_url', APIGW_URL),
                verify=False,
                credentials=c_
            )
            r = ls.write(
                vendor_id=vendor_id,
                log_type=log_type,
                json=payload
            )
            results = r.text
            status = r.status_code
        except Exception as e:
            return render_template(
                'pages/logwriter.html',
                results=str(e),
                status=500
            )
        else:
            return render_template(
                'pages/logwriter.html',
                results=results,
                status=status
            )
    else:
        return render_template(
            'pages/logwriter.html',
            results='',
            status='n/a'
        )


@views.route('/directoryexplorer', methods=['POST', 'GET'])
@login_required
def directoryexplorer():
    obj = request.form.get('object', None)
    endpoint = request.form.get('endpoint', '')
    domain = request.form.get('domain', '')
    results = {}
    s = ""
    headers = []
    settings_ = db.get_settings()
    c_ = Credentials(
        token_url=settings_.get('token_url', TOKEN_URL),
        token_revoke_url=settings_.get('revoke_token_url', REVOKE_TOKEN_URL),
        auth_base_url=settings_.get('auth_base_url', AUTHORIZATION_BASE_URL)
    )
    try:
        ds = DirectorySyncService(
            url=settings_.get('apigw_url', APIGW_URL),
            verify=False,
            credentials=c_
        )

        dispatcher = {
            'attributes': ds.attributes,
            'count': ds.count,
            'domains': ds.domains,
            'query': ds.query
        }

        m = dispatcher.get(endpoint, None)
        if m:
            if obj and endpoint == "query":
                r = m(
                    obj,
                    json={'domain': domain},
                    timeout=15
                )
                s = r.status_code
                results = r.text
            elif obj and endpoint == "count":
                r = m(
                    object_class=obj,
                    params={'domain': domain},
                    timeout=15
                )
                s = r.status_code
                results = r.text
            else:
                r = m(timeout=15)
                s = r.status_code
                results = r.text
    except Exception as e:
        return render_template(
            'pages/directoryexplorer.html',
            results=e,
            status=500,
            headers=headers,
            endpoint=None
        )
    else:
        return render_template(
            'pages/directoryexplorer.html', results=results,
            headers=headers, endpoint=endpoint, status=s
        )


@views.route('/eventexplorer', methods=['POST', 'GET'])
@login_required
def eventexplorer():
    channel_id = request.form.get('channel', 'EventFilter')
    endpoint = request.form.get('endpoint', '')
    payload = request.form.get('payload', None)
    settings_ = db.get_settings()
    c_ = Credentials(
        token_url=settings_.get('token_url', TOKEN_URL),
        token_revoke_url=settings_.get('revoke_token_url', REVOKE_TOKEN_URL),
        auth_base_url=settings_.get('auth_base_url', AUTHORIZATION_BASE_URL)
    )
    results = []
    s = ""
    try:
        es = EventService(
            url=settings_.get('apigw_url', APIGW_URL),
            verify=False,
            credentials=c_
        )
        dispatcher = {
            'get_filters': es.get_filters,
            'poll': es.poll,
            'set_filters': es.set_filters,
            'ack': es.ack,
            'nack': es.nack
        }
        m = dispatcher.get(endpoint, None)
        if m:
            if payload:
                r = m(channel_id, json=payload, timeout=15)
                s = r.status_code
                results = r.text or "SUCCESS: {}".format(endpoint)
            elif not payload and endpoint == "poll":
                r = m(channel_id, json={}, timeout=15)
                s = r.status_code
                results = r.text or "SUCCESS: {}".format(endpoint)
            else:
                r = m(channel_id, timeout=15)
                s = r.status_code
                results = r.text or "SUCCESS: {}".format(endpoint)
    except Exception as e:
        results = str(e)
        s = 500
        return render_template(
            'pages/eventexplorer.html', results=results, status=s
        )
    else:
        return render_template(
            'pages/eventexplorer.html', results=results, status=s
        )


@views.route('/updates', methods=['GET'])
@login_required
def updates():
    return render_template(
        'pages/updates.html',
        msg="",
        status=""
    )


@views.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    auth_base_url = request.form.get('auth_base_url', '')
    token_url = request.form.get('token_url', '')
    revoke_token_url = request.form.get('revoke_token_url', '')
    apigw_url = request.form.get('apigw_url', '')
    vendor = request.form.get('vendor', '')
    settings_ = db.get_settings()
    settings_['auth_base_url'] = auth_base_url or settings_.get(
        'auth_base_url', AUTHORIZATION_BASE_URL)
    settings_['token_url'] = token_url or settings_.get('token_url',
                                                        TOKEN_URL)
    settings_['revoke_token_url'] = revoke_token_url or settings_.get(
        'revoke_token_url', REVOKE_TOKEN_URL)
    settings_['apigw_url'] = apigw_url or settings_.get('apigw_url', APIGW_URL)
    settings_['vendor'] = vendor or settings_.get('vendor', VENDOR)
    db.update_settings(settings_)
    return render_template(
        'pages/settings.html',
        settings=settings_
    )


@views.route('/developer', methods=['GET'])
@login_required
def developer():
    db_ = AppDB()
    activation = db_.get_activation()
    key_ = activation.get('key', '')
    return render_template(
        'pages/developer.html',
        key=key_
    )


@views.route('/get_tokens', methods=['GET'], endpoint='get_tokens')
@auth_required('basic', 'session', 'token')
def get_tokens():
    return jsonify(
        {
            'access_token': c.access_token,
            'refresh_token': c.refresh_token,
            'client_id': c.client_id
        }
    )


@views.route('/generate_api_key', methods=['POST'])
@login_required
def generate_api_key():
    import requests
    email = request.form.get('email', current_user.email)
    password = request.form.get('password', '')
    db_ = AppDB()
    activation = db_.get_activation()
    key_ = activation.get('key', '')
    try:
        r = requests.post(
            '{}login'.format(request.url_root),
            json={'email': email, 'password': password},
            verify=False,
            timeout=3
        )
        try:
            r_json = r.json()
        except Exception as e:
            return jsonify(
                {
                    'key': 'none',
                    'msg': 'failed',
                    'reason': str(e)
                }
            )
        else:
            response = r_json.get('response', {})
            if "errors" not in response and len(response) > 0:
                user = response.get('user', {})
                key_ = user.get('authentication_token', '')
                db_ = AppDB()
                db_.update_api_key(key_)
                msg = "success"
                status = "success"
            else:
                key_ = key_
                msg = "{}".format(response)
                status = "danger"
            return render_template(
                'pages/developer.html',
                key=key_,
                msg=msg,
                status=status
            )
    except Exception as e:
        return render_template(
            'pages/developer.html',
            key=key_,
            msg="{}".format(e),
            status="danger"
        )


@views.route('/logo.png')
def logo():
    return send_from_directory(os.path.join(
        views.root_path, '../templates'), 'logo.png',
        mimetype='image/png'
    )


@views.route('/favicon.ico')
@login_required
def favicon():
    return send_from_directory(os.path.join(
        views.root_path, '../templates'), 'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )
