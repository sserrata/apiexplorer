import json
import bcrypt
import os
import uuid

import requests
from flask import render_template, send_from_directory, request, \
    redirect, session
from flask_mongoengine import MongoEngine
from flask_security import Security, MongoEngineUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from pymongo import MongoClient, errors
from requests_oauthlib import OAuth2Session

from app import app

# Uncomment for detailed oauthlib logs
import logging
import sys
log = logging.getLogger('requests_oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

app.jinja_env.cache = {}
app.config['SECRET_KEY'] = 'Q5*P0MvH11G121dt'
app.config['PERMANENT_SESSION_LIFETIME'] = 1200
app.config['SECURITY_REGISTERABLE'] = False
app.config['SECURITY_TRACKABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
app.config['SECURITY_CHANGEABLE'] = True
app.config['SECURITY_SEND_PASSWORD_CHANGE_EMAIL'] = False
# app.config['SECURITY_POST_LOGIN_VIEW'] = "/index.html"
app.config['USE_SESSION_FOR_NEXT'] = True
app.config['MONGODB_DB'] = 'security'
app.config['MONGODB_HOST'] = 'localhost'
app.config['MONGODB_PORT'] = 27017
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
SALT = 'c572A5Q7%f6p9gya'
app.config['SECURITY_PASSWORD_SALT'] = SALT
app.jinja_env.cache = {}
app.jinja_env.lstrip_blocks = True
app.jinja_env.trim_blocks = True
_db = MongoEngine(app)


class Role(_db.Document, RoleMixin):
    name = _db.StringField(max_length=80, unique=True)
    description = _db.StringField(max_length=255)


class User(_db.Document, UserMixin):
    email = _db.StringField(max_length=255)
    password = _db.StringField(max_length=255)
    active = _db.BooleanField(default=True)
    confirmed_at = _db.DateTimeField()
    roles = _db.ListField(_db.ReferenceField(Role), default=[])
    last_login_at = _db.DateTimeField()
    current_login_at = _db.DateTimeField()
    last_login_ip = _db.StringField(max_length=255)
    current_login_ip = _db.StringField(max_length=255)
    login_count = _db.IntField()
    refresh_token = _db.StringField()
    access_token = _db.StringField()
    token_type = _db.StringField(max_length=255)
    expires_in = _db.IntField()


user_datastore = MongoEngineUserDatastore(_db, User, Role)
security = Security(app, datastore=user_datastore)


class OauthDB:
    """An Oauth database instance."""
    def __init__(self):
        """Class for handling reading/writing Global settings"""
        self.mdb_client = MongoClient(
            'mongodb://localhost:27017/', maxPoolSize=50, connect=False
        )
        self.mdb = self.mdb_client['security']
        self.user = self.mdb['user']
        self.oauth = self.mdb['oauth']
        self.activation = self.mdb['activation']

    @property
    def tokens(self):
        if self.oauth.find_one({'_id': 1}):
            return True
        else:
            return False

    def update_oauth(self, oauth):
        """Store authorization tokens."""
        _type = 'urn:pingidentity.com:oauth2:validated_token'
        try:
            self.oauth.insert_one(
                {
                    '_id': 1,
                    'access_token': oauth.get('access_token', ''),
                    'refresh_token': oauth.get('refresh_token', ''),
                    'token_type': oauth.get('token_type', ''),
                    'expires_in': oauth.get('expires_in', ''),
                    'expires_at': oauth.get('expires_at', '')
                }
            )
        except errors.DuplicateKeyError:
            if oauth.get('token_type', '') == _type:
                import json
                _custom = oauth.get('access_token', '{}')
                print(session)
                try:
                    session['oauth_token']['token_type'] = oauth.get('token_type', '')
                    session['oauth_token']['expires_in'] = oauth.get('expires_in', '')
                    session['oauth_token']['client_id'] = oauth.get('client_id', '')
                    session['oauth_token']['scope'] = oauth.get('scope', '')
                    session['oauth_token']['sub'] = _custom.get('sub', '')
                    session['oauth_token']['pa_3p_tenant'] = _custom.get('pa_3p_tenant', '')
                    session['oauth_token']['username'] = _custom.get('username', '')
                except KeyError:
                    session['oauth_token'] = {}
                    o = self.get_oauth()
                    print(o)
                    session['oauth_token']['token_type'] = o.get('token_type', '')
                    session['oauth_token']['expires_in'] = o.get('expires_in', '')
                    session['oauth_token']['client_id'] = o.get('client_id', '')
                    session['oauth_token']['scope'] = o.get('scope', '')
                    session['oauth_token']['sub'] = _custom.get('sub', '')
                    session['oauth_token']['pa_3p_tenant'] = _custom.get('pa_3p_tenant', '')
                    session['oauth_token']['username'] = _custom.get('username', '')
                self.oauth.update_one(
                    {'_id': 1},
                    {
                        '$set': {
                            'token_type': oauth.get('token_type', ''),
                            'expires_in': oauth.get('expires_in', ''),
                            'client_id': oauth.get('client_id', ''),
                            'scope': oauth.get('scope', ''),
                            'sub': _custom.get('sub', ''),
                            'pa_3p_tenant': _custom.get('pa_3p_tenant', ''),
                            'username': _custom.get('username', '')
                        }
                    }
                )
            else:
                self.oauth.update_one(
                    {'_id': 1},
                    {
                        '$set': {
                            'access_token': oauth.get(
                                'access_token', ''
                            ),
                            'refresh_token': oauth.get(
                                'refresh_token', ''
                            ),
                            'token_type': oauth.get('token_type', ''),
                            'expires_in': oauth.get('expires_in', '')
                        }
                    }
                )

    def find_users(self):
        return list(self.user.find({}))

    def get_oauth(self):
        return self.oauth.find_one({'_id': 1})

    def delete_tokens(self):
        return self.oauth.drop()

    def delete_activation(self):
        return self.activation.drop()

    def update_activation(self, client):
        try:
            self.activation.insert_one(
                {
                    '_id': 1,
                    'client_id': client.get('client_id', ''),
                    'client_secret': client.get('client_secret', ''),
                    'redirect_uri': client.get('redirect_uri', ''),
                    'instance_id': client.get('instance_id', ''),
                    'scope': client.get('scope', ''),
                    'activated': client.get('activated', False),
                    'name': session.get('name', ''),
                    'email': session.get('email', ''),
                    'company': session.get('company', ''),
                    'department': session.get('department', ''),
                    'url': session.get('url', '')
                }
            )
        except errors.DuplicateKeyError:
            self.activation.update_one(
                {'_id': 1},
                {
                    '$set': {
                        'client_id': client.get('client_id', ''),
                        'client_secret': client.get(
                            'client_secret', ''
                        ),
                        'redirect_uri': client.get('redirect_uri', ''),
                        'instance_id': client.get('instance_id', ''),
                        'scope': client.get('scope', ''),
                        'activated': client.get('activated', False),
                        'name': session.get('name', ''),
                        'email': session.get('email', ''),
                        'company': session.get('company', ''),
                        'department': session.get('department', ''),
                        'url': session.get('url', '')
                    }
                }
            )

    def get_activation(self):
        return self.activation.find_one({'_id': 1})


# client_id = "v1"
# client_id = "demo-client-w-cert"
# client_secret = "9Z1fhksS8VLzr80ACf0ZzFn2bJKMcj2jT4nE7brlvlofuVDy45JaGyryRKdlEbgO"

authorization_base_url = 'https://identitytest.paloaltonetworks.com/as/authorization.oauth2'
# authorization_base_url = 'https://10.5.14.213:9031/as/authorization.oauth2'

token_url = 'https://identitytest.paloaltonetworks.com/as/token.oauth2'
# token_url = 'https://10.5.14.213:9031/as/token.oauth2'

revoke_token_url = 'https://identitytest.paloaltonetworks.com/as/revoke_token.oauth2'
# revoke_token_url = 'https://10.5.14.213:9031/as/revoke_token.oauth2'

scope = 'logging-service:read logging-service:write event-service:read event-service:write directory-sync-service:read'
tenant = 'Yellow'
# tenant = '22222'
# tenant = 'demo132bm'
validate = 'urn:pingidentity.com:oauth2:grant_type:validate_bearer'
# redirect_uri = 'http://localhost:5000/auth-callback'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


# Creates default admin user on first run - uncomment afterwards
@app.before_first_request
def create_user():
    if not user_datastore.get_user('admin'):
        user_datastore.create_user(email='admin', password='paloalto')


@app.before_request
def func():
    """Marks session as modified to force a new session"""
    session.modified = True


@app.route('/')
@app.route('/index.html')
@login_required
def index():
    # params = request.args.get('params', None)
    # if params:
    #     import base64
    #     from urllib.parse import parse_qsl
    #     params = base64.b64decode(params)
    #     x = dict(parse_qsl(params))
    #     parsed_params = {
    #         k.decode("utf-8"): v.decode("utf-8") for k, v in x.items()
    #     }
    #     instance_id = parsed_params.get('instanceId', '')
    #     region = parsed_params.get('region', '')
    #     session['instanceId'] = instance_id
    #     session['region'] = region
    # else:
    #     session['instanceId'] = ''
    #     session['region'] = ''
    return render_template('pages/index.html')


@app.route('/authorization')
@login_required
def authorization():
    db_ = OauthDB()
    oauth = session.get('oauth_token', db_.get_oauth())
    activation = db_.get_activation()
    return render_template(
        'pages/authorization.html',
        users=db_.find_users(),
        tokens=db_.tokens,
        oauth=oauth,
        activation=activation,
        alert=None,
        msg=None
    )


@app.route('/refresh_tokens')
@login_required
def refresh_tokens():
    db_ = OauthDB()
    oauth = session.get('oauth_token', db_.get_oauth())
    client = db_.get_activation()
    refresh_token = oauth['refresh_token']
    # path = 'app/lib/pancloud/examples/ssl'
    pingid = OAuth2Session()
    # pingid.cert = '{}/Apollo1Client.pem'.format(path)
    try:
        token = pingid.refresh_token(
            client_id=client.get('client_id', ''),
            refresh_token=refresh_token,
            token_url=token_url,
            verify=False,
            client_secret=client.get('client_secret', ''),
            # cert='{}/Apollo1Client.pem'.format(path),
            auth=None
        )
    except Exception as _e:
        print(_e)
        return render_template(
            'pages/authorization.html',
            users=db_.find_users(),
            tokens=db_.tokens,
            oauth=oauth,
            alert="danger",
            msg="{}".format(_e)
        )
    else:
        print(token)
        session['oauth_token'] = token
        db_ = OauthDB()
        db_.update_oauth(token)
        return render_template(
            'pages/authorization.html',
            users=db_.find_users(),
            tokens=db_.tokens,
            oauth=oauth,
            alert="success",
            msg="SUCCESS"
        )


@app.route('/validate_tokens')
@login_required
def validate_tokens():
    db_ = OauthDB()
    client = db_.get_activation()
    oauth = session.get('oauth_token', db_.get_oauth())
    access_token = oauth.get('access_token', '')
    body = {
        'client_id': client.get('client_id', ''),
        'grant_type': validate,
        'token': access_token,
        'client_secret': client.get('client_secret', '')
    }
    # path = 'app/lib/pancloud/examples/ssl'
    with requests.Session() as s:
        s.verify = False
        # s.cert = '{}/Apollo1Client.pem'.format(path)
        s.auth = None
        s.headers = '{Content-Type: application/x-www-form-urlencoded}'
        try:
            r = s.post(
                url=token_url,
                data=body
            )
            token = r.json()
        except Exception as _e:
            print(_e)
            return render_template(
                'pages/authorization.html',
                users=db_.find_users(),
                tokens=db_.tokens,
                oauth=oauth,
                alert="danger",
                msg="{}".format(_e)
            )
        else:
            token = r.json()
            db_ = OauthDB()
            db_.update_oauth(token)
            return render_template(
                'pages/authorization.html',
                users=db_.find_users(),
                tokens=db_.tokens,
                oauth=oauth,
                alert="success",
                msg="SUCCESS"
            )


@app.route('/revoke_access_token')
@login_required
def revoke_access_token():
    db_ = OauthDB()
    oauth = session.get('oauth_token', db_.get_oauth())
    access_token = oauth.get('access_token', '')
    body = {
        'client_id': client_id,
        'token': access_token,
        'token_type_hint': 'access_token',
        'client_secret': client_secret
    }
    path = 'app/lib/pancloud/examples/ssl'
    with requests.Session() as s:
        s.verify = False
        # s.cert = '{}/Apollo1Client.pem'.format(path)
        s.auth = None
        s.headers = '{Content-Type: application/x-www-form-urlencoded}'
        try:
            r = s.post(
                url=revoke_token_url,
                data=body
            )
            print(r.status_code)
        except Exception as _e:
            print(_e)
            return render_template(
                'pages/authorization.html',
                users=db_.find_users(),
                tokens=db_.tokens,
                oauth=oauth,
                alert="danger",
                msg="{}".format(_e)
            )
        else:
            print(r.content)
            return render_template(
                'pages/authorization.html',
                users=db_.find_users(),
                tokens=db_.tokens,
                oauth=oauth,
                alert="success",
                msg="SUCCESS"
            )


@app.route('/revoke_refresh_token')
@login_required
def revoke_refresh_token():
    db_ = OauthDB()
    oauth = session.get('oauth_token', db_.get_oauth())
    refresh_token = oauth.get('refresh_token', '')
    body = {
        'client_id': client_id,
        'token': refresh_token,
        'token_type_hint': 'refresh_token',
        'client_secret': client_secret
    }
    path = 'app/lib/pancloud/examples/ssl'
    with requests.Session() as s:
        s.verify = False
        # s.cert = '{}/Apollo1Client.pem'.format(path)
        s.auth = None
        s.headers = '{Content-Type: application/x-www-form-urlencoded}'
        try:
            r = s.post(
                url=revoke_token_url,
                data=body
            )
            print(r.status_code)
        except Exception as _e:
            print(_e)
            return render_template(
                'pages/authorization.html',
                users=db_.find_users(),
                tokens=db_.tokens,
                oauth=oauth,
                alert="danger",
                msg="{}".format(_e)
            )
        else:
            return render_template(
                'pages/authorization.html',
                users=db_.find_users(),
                tokens=db_.tokens,
                oauth=oauth,
                alert="success",
                msg="SUCCESS"
            )


@app.route('/delete_tokens')
@login_required
def delete_tokens():
    db_ = OauthDB()
    db_.delete_tokens()
    db_.delete_activation()
    oauth = {}
    session['oauth_token'] = {}
    return render_template(
        'pages/authorization.html',
        users=db_.find_users(),
        tokens=db_.tokens,
        oauth=oauth,
        alert="success",
        msg="SUCCESS"
    )


@app.route("/pingid", methods=['POST', 'GET'])
@login_required
def pingid():
    """Authorize user."""
    form = request.form
    client_id = form.get('client_id', None)
    client_secret = form.get('client_secret', None)
    redirect_uri = form.get('redirect_uri', None)
    instance_id = session.get('instance_id', '')
    region = session.get('region', '')
    try:
        scope = ' '.join(form.getlist('scope'))
    except (KeyError, ValueError):
        scope = ''
    client = {
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'instance_id': instance_id,
        'scope': scope
    }
    db_ = OauthDB()
    db_.update_activation(client)

    a = db_.get_activation()

    _state = uuid.uuid4()
    # body = {
    #     'client_id': client_id,
    #     'scope': scope,
    #     'redirect_uri': redirect_uri,
    #     'state': _state,
    #     'tenant': tenant
    # }
    # with requests.Session() as s:
    #     r = s.post(
    #         url='http://localhost:4000/api/v1/authorize',
    #         data=body
    #     )
    #     authorization_url = r.json().get('authorization_url', '')
    #     state = r.json().get('state', '')
    pingid = OAuth2Session(
        client_id=a.get('client_id', ''),
        scope=a.get('scope', ''),
        redirect_uri=a.get('redirect_uri', ''),
        state=_state
    )
    pingid.auth = False
    pingid.verify = False
    authorization_url, state = pingid.authorization_url(
        authorization_base_url,
        instance_id=instance_id,
        region=region
    )
    session['oauth_state'] = state
    return redirect(authorization_url)
        # session['oauth_state'] = state
        # return redirect(authorization_url)


@app.route("/auth-callback", methods=['POST', 'GET'])
def callback():
    """Retrieve an access token."""
    db_ = OauthDB()
    client = db_.get_activation()
    code = request.args.get('code', None)
    state = request.args.get('state', None)
    error = request.args.get('error', None)
    error_description = request.args.get('error_description', '')
    oauth_state = session.get('oauth_state', '')
    if oauth_state == uuid.UUID(state):
        # body = {
        #     'client_id': client_id,
        #     'code': code,
        #     'error': error,
        #     'redirect_uri': redirect_uri,
        #     'scope': scope,
        #     'state': state
        # }
        # with requests.Session() as s:
        #     r = s.post(
        #         url='http://localhost:4000/api/v1/tokens',
        #         data=body
        #     )
        #     token = r.json()
        #     print(token)
        #     session['oauth_token'] = token
        #     db_ = OauthDB()
        #     db_.update_oauth(token)
        #     return redirect('/authorization')
        # path = 'app/lib/pancloud/examples/ssl'
        pingid = OAuth2Session(
            client_id=client.get('client_id', ''),
            scope=scope,
            redirect_uri=client.get('redirect_uri', ''),
            state=state
        )
        # pingid.cert = '{}/Apollo1Client.pem'.format(path)
        pingid.auth = None
        pingid.verify = False
        try:
            token = pingid.fetch_token(
                token_url=token_url,
                client_secret=client.get('client_secret', ''),
                client_id=client.get('client_id', ''),
                code=code,
                auth=False,
                verify=False
                # cert='{}/Apollo1Client.pem'.format(path)
            )
        except Exception as _e:
            print('Exception occurred: {}'.format(_e))
            print(error)
            db_ = OauthDB()
            db_.delete_activation()
            db_.delete_tokens()
            return render_template(
                'pages/authorization.html',
                users=db_.find_users(),
                tokens=db_.tokens,
                oauth={},
                alert="danger",
                msg="{}: {}".format(error, error_description)
            )
        else:
            print(token)
            session['oauth_token'] = token
            db_ = OauthDB()
            client = db_.get_activation()
            client.update({'activated': True})
            print(client)
            db_.update_activation(client)
            db_.update_oauth(token)
            return redirect('/authorization')

    db_ = OauthDB()
    return render_template(
        'pages/authorization.html',
        users=db_.find_users(),
        tokens=db_.tokens,
        oauth={},
        alert="danger",
        msg="STATE MISMATCH: Possible CSRF detected!"
    )


@app.route('/queryexplorer', methods=['POST', 'GET'])
@login_required
def queryexplorer():
    db_ = OauthDB()
    oauth = db_.get_oauth() or session.get('oauth_token', '')
    try:
        _token = oauth.get('access_token', '')
    except AttributeError:
        _token = ''
    from .lib.pancloud.pancloud.logging import LoggingService
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
    print(starttime, endtime)

    # url = 'https://api.lc.prod.us.cs.paloaltonetworks.com'
    url = 'https://dc10-appproxy01-beta1.ap.pan.local'
    # _url = 'https://apigw-qa6.us.paloaltonetworks.com'
    # path = 'app/lib/pancloud/examples/ssl'
    response = []
    start = time.time()
    if starttime and endtime:
        ls = LoggingService(
            url=url,
            # cert='{}/lcaas_certificate.pem'.format(path),
            verify=False,
            headers={'Authorization': 'Bearer {}'.format(_token)},
        )

        # Prepare 'query' data
        data = {
            "query": "{}".format(_query),
            "startTime": int(starttime),
            "endTime": int(endtime),
            "maxWaitTime": 0
        }
        q = ls.query(data)
        if 'error' not in q.text:
            try:
                query_id = q.json()['queryId']
                data = {
                    "maxWaitTime": 10000
                }
                for page in ls.iter_poll(query_id, 0, params=data):
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
                    except Exception as e:
                        print(
                            "{}: queryId: {}, sequenceNo: {}".format(
                                page.json()['queryStatus'],
                                page.json()['queryId'],
                                page.json()['sequenceNo']
                            )
                        )
                ls.delete(query_id)
            except Exception as e:
                response = q.text
        else:
            response = q.text
    et = time.time() - start
    headers = []
    tabular = False
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
        json_response = {}
    return render_template(
        'pages/queryexplorer.html', response=response, sd=starttime,
        ed=endtime, et=et, headers=headers, tabular=tabular,
        json=json_response
    )


@app.route('/directoryexplorer', methods=['POST', 'GET'])
@login_required
def directoryexplorer():
    _obj = request.form.get('object', None)
    endpoint = request.form.get('endpoint', '')
    domain = request.form.get('domain', '')

    from .lib.pancloud.pancloud.directorysync import DirectorySyncService

    results = {}
    headers = []
    # url = 'https://app-stg1.directorysync.paloaltonetworks.com'
    db_ = OauthDB()
    oauth = db_.get_oauth() or session.get('oauth_token', '')
    try:
        _token = oauth.get('access_token', '')
    except AttributeError:
        _token = ''
    url = 'https://dc10-appproxy01-beta1.ap.pan.local'
    # url = 'https://apigw-qa6.us.paloaltonetworks.com'

    path = 'app/lib/pancloud/examples/ssl'
    # Create Logging Service instance
    ds = DirectorySyncService(
        url=url,
        # cert='{}/ds.client.pem'.format(path),
        verify=False,
        headers={'Authorization': 'Bearer {}'.format(_token)}
        # raise_for_status=True
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
            if _obj and endpoint == "query":
                r = m(_obj, timeout=15)
                print(r.text)
                print(r.status_code)
                results = r.text
                return render_template(
                    'pages/directoryexplorer.html', results=results,
                    headers=headers, endpoint=endpoint
                )
            elif _obj and endpoint == "count":
                print(_obj, domain)
                r = m(
                    object_class=_obj,
                    params={'domain': domain},
                    timeout=15
                )
                print(r.url)
                print(r.text)
                results = r.text
                return render_template(
                    'pages/directoryexplorer.html', results=results,
                    headers=headers, endpoint=endpoint
                )
            else:
                data = {
                    "tenantId": "Yellow"
                }
                r = m(
                    data=data,
                    timeout=15
                )
                print(r.text)
                results = r.text
                return render_template(
                    'pages/directoryexplorer.html', results=results,
                    headers=headers, endpoint=endpoint
                )
        except Exception as e:
            return render_template(
                'pages/directoryexplorer.html',
                results=e,
                headers=headers,
                endpoint=None
            )
    else:
        return render_template(
            'pages/directoryexplorer.html',
            results=results,
            headers=headers,
            endpoint=None
        )


@app.route('/eventexplorer', methods=['POST', 'GET'])
@login_required
def eventexplorer():
    channel_id = request.form.get('channel', '')
    endpoint = request.form.get('endpoint', '')
    payload = request.form.get('payload', None)
    from .lib.pancloud.pancloud.event import EventService
    db_ = OauthDB()
    oauth = db_.get_oauth() or session.get('oauth_token', '')
    try:
        _token = oauth.get('access_token', '')
    except AttributeError:
        _token = ''
    _url = 'https://dc10-appproxy01-beta1.ap.pan.local'
    # _url = 'https://apigw-qa6.us.paloaltonetworks.com'
    es = EventService(
        url=_url,
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
                print(payload)
                r = m(channel_id, data=payload, timeout=15)
                print(r.request.headers)
                print(r.text)
                print(r.status_code)
                r = "Response Code: {}, Message: {}".format(
                    r.status_code,
                    r.text
                )
            else:
                r = m(channel_id, timeout=15)
                print(r.request.headers)
                try:
                    print(r.json())
                    print(r.status_code)
                    try:
                        b64 = r.json()[0].get('event', None)
                    except KeyError:
                        response = r.json()
                    else:
                        if b64:
                            import base64
                            response = base64.b64decode(b64)
                        else:
                            response = r.json()
                    r = "Response Code: {}, Message (json): {}".format(
                        r.status_code,
                        response
                    )
                except Exception as e:
                    r = "Response Code: {}, Message (text): {}".format(
                        r.status_code,
                        r.text
                    )
        except Exception as e:
            r = "Message (error): {}".format(
                e
            )
    else:
        r = {}
    return render_template(
        'pages/eventexplorer.html', results=r
    )


@app.route('/logging')
@login_required
def logging():
    return render_template('pages/logging.html')


@app.route('/event')
@login_required
def event():
    return render_template('pages/event.html')


@app.route('/directorysync')
@login_required
def directorysync():
    return render_template('pages/directorysync.html')


@app.route('/intro')
@login_required
def intro():
    return render_template('pages/intro.html')


@app.route('/favicon.ico')
@login_required
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'templates'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/logo.png')
def logo():
    return send_from_directory(os.path.join(app.root_path, 'templates'),
                               'logo.png', mimetype='image/png')


@app.context_processor
def get_global_variables():
    print(session)
    db_ = OauthDB()
    client = db_.get_activation()
    try:
        if client.get('activated', False):
            activated = True
        else:
            activated = False
    except AttributeError:
        activated = False
    return dict(activated=activated)


@security.login_context_processor
def login_register_processor():
    if not session.get('instance_id', None):
        x = request.args.to_dict()
        params = x.get('params', None)
        if params:
            import base64
            from urllib.parse import parse_qsl
            params = base64.b64decode(params)
            x = dict(parse_qsl(params))
            parsed_params = {
                k.decode("utf-8"): v.decode("utf-8") for k, v in x.items()
            }
            instance_id = parsed_params.get('instance_id', '')
            region = parsed_params.get('region', '')
            name = parsed_params.get('name', '')
            email = parsed_params.get('email', '')
            company = parsed_params.get('company', '')
            department = parsed_params.get('department', '')
            url = parsed_params.get('url', '')
            session['instance_id'] = instance_id
            session['region'] = region
            session['name'] = name
            session['email'] = email
            session['company'] = company
            session['department'] = department
            session['url'] = url
        else:
            session['instance_id'] = ''
            session['region'] = ''
            session['name'] = ''
            session['email'] = ''
            session['company'] = ''
            session['department'] = ''
            session['url'] = ''
    return dict()

