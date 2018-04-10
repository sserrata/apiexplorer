from flask import session
from tinymongo import TinyMongoClient, DuplicateKeyError

from api_explorer.constants import DB_DIR_PATH


class OAuthDB(object):
    """An Oauth database instance."""
    def __init__(self):
        self.connection = TinyMongoClient(DB_DIR_PATH)
        self.app = self.connection.app
        self.oauth = self.app.oauth
        self.activation = self.app.activation
        self.settings = self.app.settings

    @property
    def has_tokens(self):
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
                    'region': client.get('region', ''),
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
                        'region': client.get('region', ''),
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
                    'apigw_url': settings_.get('apigw_url', ''),
                    'vendor': settings_.get('vendor', '')
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
                        'apigw_url': settings_.get('apigw_url', ''),
                        'vendor': settings_.get('vendor', '')
                    }
                }
            )
