import json
import uuid
import os

from flask import render_template, request, redirect, session, jsonify, Blueprint, send_from_directory
from flask_security import login_required, auth_required, current_user
from pancloud.event import EventService
from requests_oauthlib import OAuth2Session

from api_explorer.constants import APIGW_URL, AUTHORIZATION_BASE_URL, TOKEN_URL, REVOKE_TOKEN_URL, VENDOR
from api_explorer.oauth_db import OAuthDB

views = Blueprint('views', __name__)


@views.route('/')
@views.route('/index.html')
@login_required
def index():
    return render_template('pages/index.html')


@views.route('/authorization')
@login_required
def authorization():
    db_ = OAuthDB()
    oauth = session.get('oauth_token', db_.get_oauth())
    activation = db_.get_activation() or {}
    return render_template(
        'pages/authorization.html',
        has_has_tokens=db_.has_tokens,
        oauth=oauth,
        activation=activation,
        alert=None,
        msg=None
    )


@views.route('/refresh_tokens')
@auth_required('basic', 'session', 'token')
def refresh_tokens():
    db_ = OAuthDB()
    oauth = session.get('oauth_token', db_.get_oauth())
    client = db_.get_activation()
    refresh_token = oauth['refresh_token']
    idp_ = OAuth2Session()
    activation = db_.get_activation()
    settings_ = db_.get_settings()
    try:
        token = idp_.refresh_token(
            client_id=client.get('client_id', ''),
            refresh_token=refresh_token,
            token_url=settings_.get('token_url', TOKEN_URL),
            verify=False,
            client_secret=client.get('client_secret', ''),
            auth=None
        )
    except Exception as _e:
        print(_e)
        return render_template(
            'pages/authorization.html',
            has_tokens=db_.has_tokens,
            oauth=oauth,
            activation=activation,
            alert="danger",
            msg="{}".format(_e)
        )
    else:
        session['oauth_token'] = token
        db_ = OAuthDB()
        if request.args.get('v', default='html') == 'json':
            return jsonify(token)
        db_.update_oauth(token)
        return render_template(
            'pages/authorization.html',
            has_tokens=db_.has_tokens,
            oauth=oauth,
            activation=activation,
            alert="success",
            msg="SUCCESS"
        )


@views.route('/revoke_access_token')
@login_required
def revoke_access_token():
    import requests
    db_ = OAuthDB()
    oauth = session.get('oauth_token', db_.get_oauth())
    activation = db_.get_activation()
    settings_ = db_.get_settings()
    body = {
        'client_id': activation.get('client_id', ''),
        'token': activation.get('access_token', ''),
        'token_type_hint': 'access_token',
        'client_secret': activation.get('client_secret', '')
    }
    with requests.Session() as s:
        s.verify = False
        s.auth = None
        s.headers = '{Content-Type: application/x-www-form-urlencoded}'
        try:
            s.post(
                url=settings_.get('revoke_token_url', REVOKE_TOKEN_URL),
                data=body
            )
        except Exception as _e:
            print(_e)
            return render_template(
                'pages/authorization.html',
                has_tokens=db_.has_tokens,
                oauth=oauth,
                alert="danger",
                msg="{}".format(_e)
            )
        else:
            return render_template(
                'pages/authorization.html',
                has_tokens=db_.has_tokens,
                oauth=oauth,
                alert="success",
                msg="SUCCESS"
            )


@views.route('/revoke_refresh_token')
@login_required
def revoke_refresh_token():
    import requests
    db_ = OAuthDB()
    oauth = session.get('oauth_token', db_.get_oauth())
    activation = db_.get_activation()
    settings_ = db_.get_settings()
    body = {
        'client_id': activation.get('client_id', ''),
        'token': activation.get('refresh_token', ''),
        'token_type_hint': 'refresh_token',
        'client_secret': activation.get('client_secret', '')
    }
    with requests.Session() as s:
        s.verify = False
        s.auth = None
        s.headers = '{Content-Type: application/x-www-form-urlencoded}'
        try:
            s.post(
                url=settings_.get('revoke_token_url', REVOKE_TOKEN_URL),
                data=body
            )
        except Exception as _e:
            print(_e)
            return render_template(
                'pages/authorization.html',
                has_tokens=db_.has_tokens,
                oauth=oauth,
                alert="danger",
                msg="{}".format(_e)
            )
        else:
            return render_template(
                'pages/authorization.html',
                has_tokens=db_.has_tokens,
                oauth=oauth,
                alert="success",
                msg="SUCCESS"
            )


@views.route('/delete_tokens')
@login_required
def delete_tokens():
    db_ = OAuthDB()
    db_.delete_tokens()
    db_.delete_activation()
    oauth = {}
    activation = db_.get_activation() or {}
    session['oauth_token'] = {}
    return render_template(
        'pages/authorization.html',
        has_tokens=db_.has_tokens,
        oauth=oauth,
        activation=activation,
        alert="success",
        msg="SUCCESS"
    )


@views.route("/idp", methods=['POST', 'GET'])
@login_required
def idp():
    """Authorize user."""
    db_ = OAuthDB()
    activation = db_.get_activation()
    settings_ = db_.get_settings()
    form = request.form
    client_id = form.get('client_id', None) or activation.get('client_id', '')
    client_secret = form.get('client_secret', None) or activation.get('client_secret', '')
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
    db_.update_activation(activation_fields)
    activation = db_.get_activation()
    _state = uuid.uuid4()
    idp_ = OAuth2Session(
        client_id=activation.get('client_id', ''),
        scope=activation.get('scope', ''),
        redirect_uri=activation.get('redirect_uri', ''),
        state=_state
    )
    idp_.auth = False
    idp_.verify = False
    authorization_url, state = idp_.authorization_url(
        settings_.get('auth_base_url', AUTHORIZATION_BASE_URL),
        instance_id=instance_id,
        region=region
    )
    session['oauth_state'] = state
    return redirect(authorization_url)


@views.route("/auth-callback", methods=['POST', 'GET'])
def callback():
    """Retrieve an access token."""
    db_ = OAuthDB()
    activation = db_.get_activation()
    settings_ = db_.get_settings()
    code = request.args.get('code', None)
    state = request.args.get('state', None)
    error = request.args.get('error', None)
    error_description = request.args.get('error_description', '')
    oauth_state = session.get('oauth_state', '')
    try:
        if oauth_state == uuid.UUID(state):
            idp_ = OAuth2Session(
                client_id=activation.get('client_id', ''),
                redirect_uri=activation.get('redirect_uri', ''),
                state=state
            )
            idp_.auth = None
            idp_.verify = False
            try:
                token = idp_.fetch_token(
                    token_url=settings_.get('token_url', TOKEN_URL),
                    client_secret=activation.get('client_secret', ''),
                    client_id=activation.get('client_id', ''),
                    code=code,
                    auth=False,
                    verify=False
                )
            except Exception as _e:
                print('Exception occurred: {}'.format(_e))
                print(error)
                db_ = OAuthDB()
                db_.delete_activation()
                db_.delete_tokens()
                if error:
                    return render_template(
                        'pages/authorization.html',
                        has_tokens=db_.has_tokens,
                        oauth={},
                        activation={},
                        alert="danger",
                        msg="{}: {}".format(error, error_description)
                    )
                else:
                    return render_template(
                        'pages/authorization.html',
                        has_tokens=db_.has_tokens,
                        oauth={},
                        activation={},
                        alert="danger",
                        msg="{}".format(_e)
                    )
            else:
                session['oauth_token'] = token
                db_ = OAuthDB()
                activation = db_.get_activation()
                activation.update({'activated': True})
                db_.update_activation(activation)
                db_.update_oauth(token)
                return redirect('/authorization')
        return render_template(
            'pages/authorization.html',
            has_tokens=db_.has_tokens,
            oauth={},
            alert="danger",
            msg="STATE MISMATCH: Possible CSRF detected!"
        )
    except Exception as e:
        return render_template(
            'pages/authorization.html',
            has_tokens=db_.has_tokens,
            oauth={},
            alert="danger",
            msg="{}".format(e)
        )


@views.route('/queryexplorer', methods=['POST', 'GET'])
@login_required
def queryexplorer():
    db_ = OAuthDB()
    oauth = db_.get_oauth() or session.get('oauth_token', '')
    settings_ = db_.get_settings()
    try:
        _token = oauth.get('access_token', '')
    except AttributeError:
        _token = ''
    from pancloud.logging import LoggingService
    import datetime
    import time
    try:
        _from = request.form['from']
        if len(_from) > 0 and _from != 'None':
            _from = datetime.datetime.fromtimestamp(int(_from)).replace(
                microsecond=0).timestamp()
        else:
            _from = (datetime.datetime.utcnow() - datetime.timedelta(
                minutes=15)).replace(microsecond=0).timestamp()
    except (KeyError, ValueError):
        _from = None

    try:
        _to = request.form['to']
        if len(_to) > 0 and _to != 'None':
            _to = datetime.datetime.fromtimestamp(int(_to)).replace(
                microsecond=0).timestamp()
        else:
            _to = datetime.datetime.utcnow().replace(
                microsecond=0).timestamp()
    except (KeyError, ValueError):
        _to = None

    try:
        _query = request.form['query']
        if len(_query) > 0:
            _query = _query
        else:
            _query = 'select * from panw.traffic'
    except (KeyError, ValueError):
        _query = 'select * from panw.traffic limit 100'

    starttime = _from
    endtime = _to

    response = []
    s = ""
    start = time.time()
    if starttime and endtime:
        ls = LoggingService(
            url=settings_.get('apigw_url', APIGW_URL),
            verify=False,
            headers={'Authorization': 'Bearer {}'.format(_token)}
        )

        # Prepare 'query' data
        data = {
            "query": "{}".format(_query),
            "startTime": int(starttime),
            "endTime": int(endtime),
            "maxWaitTime": 0
        }
        try:
            q = ls.query(data, timeout=15)
            if 'error' not in q.text:
                try:
                    query_id = q.json()['queryId']
                    data = {
                        "maxWaitTime": 10000
                    }
                    for page in ls.iter_poll(query_id, 0, params=data, timeout=15):
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
                json=None, status=s
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


@views.route('/directoryexplorer', methods=['POST', 'GET'])
@login_required
def directoryexplorer():
    obj = request.form.get('object', None)
    endpoint = request.form.get('endpoint', '')
    domain = request.form.get('domain', '')

    from pancloud.directorysync import DirectorySyncService

    results = {}
    s = ""
    headers = []
    db_ = OAuthDB()
    oauth = db_.get_oauth() or session.get('oauth_token', '')
    settings_ = db_.get_settings()
    try:
        _token = oauth.get('access_token', '')
    except AttributeError:
        _token = ''

    # Create Logging Service instance
    ds = DirectorySyncService(
        url=settings_.get('apigw_url', APIGW_URL),
        verify=False,
        headers={'Authorization': 'Bearer {}'.format(_token)}
    )

    dispatcher = {
        'attributes': ds.attributes,
        'count': ds.count,
        'domains': ds.domains,
        'query': ds.query
    }

    m = dispatcher.get(endpoint, None)
    if m:
        try:
            if obj and endpoint == "query":
                r = m(obj, timeout=15)
                s = r.status_code
                results = r.text
                return render_template(
                    'pages/directoryexplorer.html', results=results,
                    headers=headers, endpoint=endpoint, status=s
                )
            elif obj and endpoint == "count":
                r = m(
                    object_class=obj,
                    params={'domain': domain},
                    timeout=15
                )
                s = r.status_code
                results = r.text
                return render_template(
                    'pages/directoryexplorer.html', results=results,
                    headers=headers, endpoint=endpoint, status=s
                )
            else:
                r = m(
                    timeout=15
                )
                s = r.status_code
                results = r.text
                return render_template(
                    'pages/directoryexplorer.html', results=results,
                    headers=headers, endpoint=endpoint, status=s
                )
        except Exception as e:
            return render_template(
                'pages/directoryexplorer.html',
                results=e,
                status=s,
                headers=headers,
                endpoint=None
            )
    else:
        return render_template(
            'pages/directoryexplorer.html',
            results=results,
            status=s,
            headers=headers,
            endpoint=None
        )


@views.route('/eventexplorer', methods=['POST', 'GET'])
@login_required
def eventexplorer():
    channel_id = request.form.get('channel', 'EventFilter')
    endpoint = request.form.get('endpoint', '')
    payload = request.form.get('payload', None)
    db_ = OAuthDB()
    oauth = db_.get_oauth() or session.get('oauth_token', '')
    settings_ = db_.get_settings()
    try:
        _token = oauth.get('access_token', '')
    except AttributeError:
        _token = ''
    es = EventService(
        url=settings_.get('apigw_url', APIGW_URL),
        verify=False,
        headers={'Authorization': 'Bearer {}'.format(_token)}
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
        try:
            if payload:
                r = m(channel_id, data=payload, timeout=15)
                s = r.status_code
                r = r.text
            else:
                r = m(channel_id, timeout=15)
                s = r.status_code
                r = r.text
        except Exception as e:
            r = "Message (error): {}".format(
                e
            )
            s = ""
    else:
        r = {}
        s = ""
    return render_template(
        'pages/eventexplorer.html', results=r, status=s
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
    db_ = OAuthDB()
    settings_ = db_.get_settings()
    settings_['auth_base_url'] = auth_base_url or settings_.get('auth_base_url', AUTHORIZATION_BASE_URL)
    settings_['token_url'] = token_url or settings_.get('token_url', TOKEN_URL)
    settings_['revoke_token_url'] = revoke_token_url or settings_.get('revoke_token_url', REVOKE_TOKEN_URL)
    settings_['apigw_url'] = apigw_url or settings_.get('apigw_url', APIGW_URL)
    settings_['vendor'] = vendor or settings_.get('vendor', VENDOR)
    db_.update_settings(settings_)
    return render_template(
        'pages/settings.html',
        settings=settings_
    )


@views.route('/developer', methods=['GET'])
@login_required
def developer():
    db_ = OAuthDB()
    activation = db_.get_activation()
    key_ = activation.get('key', '')
    return render_template(
        'pages/developer.html',
        key=key_
    )


@views.route('/get_tokens', methods=['GET'], endpoint='get_tokens')
@auth_required('basic', 'session', 'token')
def get_tokens():
    db_ = OAuthDB()
    oauth = db_.get_oauth()
    return jsonify(oauth)


@views.route('/generate_api_key', methods=['POST'])
@login_required
def generate_api_key():
    import requests
    email = request.form.get('email', current_user.email)
    password = request.form.get('password', '')
    db_ = OAuthDB()
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
                db_ = OAuthDB()
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
