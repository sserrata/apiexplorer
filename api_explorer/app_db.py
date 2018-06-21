from tinymongo import TinyMongoClient, DuplicateKeyError

from api_explorer.constants import DB_DIR_PATH


class AppDB(object):
    """An Oauth database instance."""
    def __init__(self):
        self.connection = TinyMongoClient(DB_DIR_PATH)
        self.app = self.connection.app
        self.activation = self.app.activation
        self.settings = self.app.settings

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
                        'client_secret': client.get('client_secret', ''),
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
                    'apigw_url': settings_.get('apigw_url', ''),
                    'vendor': settings_.get('vendor', '')
                }
            )
        except DuplicateKeyError:
            self.settings.update_one(
                {'_id': 1},
                {
                    '$set': {
                        'apigw_url': settings_.get('apigw_url', ''),
                        'vendor': settings_.get('vendor', '')
                    }
                }
            )
