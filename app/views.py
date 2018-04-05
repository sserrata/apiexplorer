import json
import os
import uuid
from tinymongo import TinyMongoClient, DuplicateKeyError

from flask import render_template, send_from_directory, request, \
    redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, auth_required, current_user
from requests_oauthlib import OAuth2Session
from app import app

# Uncomment for detailed oauthlib logs
import logging
import sys
log = logging.getLogger('requests_oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

app.jinja_env.cache = {}
app.config['SECRET_KEY'] = '8Q@U99a3wd8NGuY*nRTJ#WAk4r'
app.config['PERMANENT_SESSION_LIFETIME'] = 1200
app.config['SECURITY_REGISTERABLE'] = False
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

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + basedir + '/db/security.db'
db = SQLAlchemy(app)

# Define models
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(100))
    current_login_ip = db.Column(db.String(100))
    login_count = db.Column(db.Integer)
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship(
        'Role', secondary=roles_users,
        backref=db.backref('users', lazy='dynamic')
    )


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


class OauthDB:
    """An Oauth database instance."""
    def __init__(self):
        self.connection = TinyMongoClient(basedir + '/db/')
        self.app = self.connection.app
        self.oauth = self.app.oauth
        self.activation = self.app.activation
        self.settings = self.app.settings

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
        except DuplicateKeyError:
            if oauth.get('token_type', '') == _type:
                import json
                _custom = oauth.get('access_token', '{}')
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

    def get_oauth(self):
        return self.oauth.find_one({'_id': 1}) or {}

    def delete_tokens(self):
        try:
            return self.oauth.delete_one({'_id': 1})
        except TypeError:
            return

    def delete_activation(self):
        try:
            return self.activation.delete_one({'_id': 1})
        except TypeError:
            return

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
                }
            )
        except DuplicateKeyError:
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
                    }
                }
            )

    def get_activation(self):
        return self.activation.find_one({'_id': 1}) or {}

    def get_settings(self):
        return self.settings.find_one({'_id': 1}) or {}

    def update_api_key(self, key):
        try:
            self.activation.insert_one(
                {
                    '_id': 1,
                    'key': key
                }
            )
        except DuplicateKeyError:
            self.activation.update_one(
                {'_id': 1},
                {
                    '$set': {
                        'key': key
                    }
                }
            )

    def update_settings(self, settings_):
        try:
            self.settings.insert_one(
                {
                    '_id': 1,
                    'auth_base_url': settings_.get('auth_base_url', ''),
                    'token_url': settings_.get('token_url', ''),
                    'revoke_token_url': settings_.get(
                        'revoke_token_url', ''
                    ),
                    'apigw_url': settings_.get('apigw_url', '')
                }
            )
        except DuplicateKeyError:
            self.settings.update_one(
                {'_id': 1},
                {
                    '$set': {
                        'auth_base_url': settings_.get('auth_base_url',
                                                       ''),
                        'token_url': settings_.get('token_url', ''),
                        'revoke_token_url': settings_.get(
                            'revoke_token_url', ''
                        ),
                        'apigw_url': settings_.get('apigw_url', '')
                    }
                }
            )


AUTHORIZATION_BASE_URL = 'https://identity.paloaltonetworks.com/as/authorization.oauth2'
TOKEN_URL = 'https://api.paloaltonetworks.com/api/oauth2/RequestToken'
REVOKE_TOKEN_URL = 'https://api.paloaltonetworks.com/api/oauth2/RevokeToken'
APIGW_URL = 'https://apigw-stg4.us.paloaltonetworks.com'


# Creates default admin user on first run - uncomment afterwards
@app.before_first_request
def create_user():
    try:
        if not user_datastore.get_user('admin'):
            db.create_all()
            user_datastore.create_user(email='admin', password='paloalto')
            db.session.commit()
    except Exception as e:
        print(e)
        db.create_all()
        user_datastore.create_user(email='admin', password='paloalto')
        db.session.commit()


@app.before_request
def func():
    """Marks session as modified to force a new session"""
    session.modified = True


@app.route('/')
@app.route('/index.html')
@login_required
def index():
    return render_template('pages/index.html')


@app.route('/authorization')
@login_required
def authorization():
    db_ = OauthDB()
    oauth = session.get('oauth_token', db_.get_oauth())
    activation = db_.get_activation()
    return render_template(
        'pages/authorization.html',
        tokens=db_.tokens,
        oauth=oauth,
        activation=activation,
        alert=None,
        msg=None
    )


@app.route('/refresh_tokens')
@auth_required('basic', 'session', 'token')
def refresh_tokens():
    db_ = OauthDB()
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
            tokens=db_.tokens,
            oauth=oauth,
            activation=activation,
            alert="danger",
            msg="{}".format(_e)
        )
    else:
        session['oauth_token'] = token
        db_ = OauthDB()
        db_.update_oauth(token)
        return render_template(
            'pages/authorization.html',
            tokens=db_.tokens,
            oauth=oauth,
            activation=activation,
            alert="success",
            msg="SUCCESS"
        )


@app.route('/revoke_access_token')
@login_required
def revoke_access_token():
    import requests
    db_ = OauthDB()
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
                tokens=db_.tokens,
                oauth=oauth,
                alert="danger",
                msg="{}".format(_e)
            )
        else:
            return render_template(
                'pages/authorization.html',
                tokens=db_.tokens,
                oauth=oauth,
                alert="success",
                msg="SUCCESS"
            )


@app.route('/revoke_refresh_token')
@login_required
def revoke_refresh_token():
    import requests
    db_ = OauthDB()
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
                tokens=db_.tokens,
                oauth=oauth,
                alert="danger",
                msg="{}".format(_e)
            )
        else:
            return render_template(
                'pages/authorization.html',
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
        tokens=db_.tokens,
        oauth=oauth,
        alert="success",
        msg="SUCCESS"
    )


@app.route("/idp", methods=['POST', 'GET'])
@login_required
def idp():
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
    activation = db_.get_activation()
    settings_ = db_.get_settings()

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


@app.route("/auth-callback", methods=['POST', 'GET'])
def callback():
    """Retrieve an access token."""
    db_ = OauthDB()
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
                db_ = OauthDB()
                db_.delete_activation()
                db_.delete_tokens()
                return render_template(
                    'pages/authorization.html',
                    tokens=db_.tokens,
                    oauth={},
                    alert="danger",
                    msg="{}: {}".format(error, error_description)
                )
            else:
                session['oauth_token'] = token
                db_ = OauthDB()
                activation = db_.get_activation()
                activation.update({'activated': True})
                db_.update_activation(activation)
                db_.update_oauth(token)
                return redirect('/authorization')
        return render_template(
            'pages/authorization.html',
            tokens=db_.tokens,
            oauth={},
            alert="danger",
            msg="STATE MISMATCH: Possible CSRF detected!"
        )
    except Exception as e:
        return render_template(
            'pages/authorization.html',
            tokens=db_.tokens,
            oauth={},
            alert="danger",
            msg="{}".format(e)
        )


@app.route('/queryexplorer', methods=['POST', 'GET'])
@login_required
def queryexplorer():
    db_ = OauthDB()
    oauth = db_.get_oauth() or session.get('oauth_token', '')
    activation = db_.get_activation()
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


@app.route('/directoryexplorer', methods=['POST', 'GET'])
@login_required
def directoryexplorer():
    obj = request.form.get('object', None)
    endpoint = request.form.get('endpoint', '')
    domain = request.form.get('domain', '')

    from pancloud.directorysync import DirectorySyncService

    results = {}
    s = ""
    headers = []
    db_ = OauthDB()
    oauth = db_.get_oauth() or session.get('oauth_token', '')
    activation = db_.get_activation()
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
                data = {
                    "tenantId": "Yellow"
                }
                r = m(
                    data=data,
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


@app.route('/eventexplorer', methods=['POST', 'GET'])
@login_required
def eventexplorer():
    channel_id = request.form.get('channel', 'EventFilter')
    endpoint = request.form.get('endpoint', '')
    payload = request.form.get('payload', None)
    from pancloud.event import EventService
    db_ = OauthDB()
    oauth = db_.get_oauth() or session.get('oauth_token', '')
    activation = db_.get_activation()
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


@app.route('/updates', methods=['GET'])
@login_required
def updates():
    return render_template(
        'pages/updates.html',
        msg="",
        status=""
    )


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    settings_ = {}
    auth_base_url = request.form.get('auth_base_url', '')
    token_url = request.form.get('token_url', '')
    revoke_token_url = request.form.get('revoke_token_url', '')
    apigw_url = request.form.get('apigw_url', '')
    db_ = OauthDB()
    settings_['auth_base_url'] = auth_base_url or AUTHORIZATION_BASE_URL
    settings_['token_url'] = token_url or TOKEN_URL
    settings_['revoke_token_url'] = revoke_token_url or REVOKE_TOKEN_URL
    settings_['apigw_url'] = apigw_url or APIGW_URL
    db_.update_settings(settings_)

    settings = db_.get_settings()

    return render_template(
        'pages/settings.html',
        settings=settings
    )


@app.route('/developer', methods=['GET'])
@login_required
def developer():
    db_ = OauthDB()
    activation = db_.get_activation()
    key_ = activation.get('key', '')
    return render_template(
        'pages/developer.html',
        key=key_
    )


@app.route('/check_for_updates', methods=['GET'])
@login_required
def check_for_updates():
    from github import Github
    import ssl
    g = Github()
    try:
        o = g.get_organization('PaloAltoNetworks')
        r = o.get_repo('apiexplorer')
    except Exception as e:
        return render_template(
            'pages/updates.html',
            msg="{}".format(e),
            status="danger"
        )
    else:
        try:
            last_commit = r.get_commits()[0].sha
        except (TypeError, KeyError):
            last_commit = ''
        with open('.git/logs/HEAD', 'rb') as logs:
            last = logs.readlines()[-1].decode()
            commit = last.split(' ')[1]
        if commit == last_commit:
            return render_template(
                'pages/updates.html',
                msg="Update available",
                status="warning"
            )
        else:
            return render_template(
                'pages/updates.html',
                msg="No Updates Available",
                status="success"
            )


@app.route('/update', methods=['GET'])
@login_required
def update():
    import requests
    import zipfile
    from shutil import copyfile
    old = '/opt/apiexplorer.old'
    current = '/opt/apiexplorer'
    master = '/opt/apiexplorer-master'
    appdb = '/opt/apiexplorer.old/app/db/app.json'
    securitydb = '/opt/apiexplorer.old/app/db/security.db'
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
        import shutil
        shutil.move(current, old)
        zip_ref = zipfile.ZipFile('/tmp/apiexplorer.zip', 'r')
        zip_ref.extractall('/opt')
        zip_ref.close()
        shutil.move(master, current)
        copyfile(appdb, '/opt/apiexplorer/app/db/app.json')
        copyfile(securitydb, '/opt/apiexplorer/app/db/security.json')
        os.remove('/tmp/apiexplorer.zip')
        shutil.rmtree(old, ignore_errors=True)
        import subprocess
        import pwd
        user = pwd.getpwuid(os.geteuid()).pw_name
        subprocess.call(
            ["/usr/bin/chown", "-R", "{user}:{user}".format(user=user), current], shell=False
        )
        subprocess.call(
            ["/usr/bin/sudo", "/usr/sbin/service", "gunicorn", "restart"], shell=False
        )
        return render_template(
            'pages/updates.html',
            msg="Success",
            status="success"
        )


@app.route('/restart_process')
@login_required
def restart_process():
    import subprocess
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


def get_procs():
    import psutil
    master = ['nginx']
    processes = []
    for p in psutil.process_iter():
        print(p.name())
        if p.name() in master:
            processes.append(p.name())
    return processes


@app.route('/get_tokens', methods=['GET'], endpoint='get_tokens')
@auth_required('basic', 'session', 'token')
def get_tokens():
    db_ = OauthDB()
    oauth = db_.get_oauth()
    return jsonify(oauth)


@app.route('/generate_api_key', methods=['POST'])
@login_required
def generate_api_key():
    import requests
    email = request.form.get('email', current_user.email)
    password = request.form.get('password', '')
    db_ = OauthDB()
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
                db_ = OauthDB()
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
    db_ = OauthDB()
    client = db_.get_activation()
    try:
        if client.get('activated', False):
            activated = True
        else:
            activated = False
    except AttributeError:
        activated = False
    nginx = get_procs()
    return dict(activated=activated, nginx=nginx)


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
            url = parsed_params.get('url', '')
            session['instance_id'] = instance_id
            session['region'] = region
        else:
            session['instance_id'] = ''
            session['region'] = ''
    return dict()

