import os

dir_path = os.path.dirname(os.path.abspath(__file__))

DB_DIR_PATH = os.path.join(dir_path, 'db')
AUTHORIZATION_BASE_URL = 'https://identity.paloaltonetworks.com/as/authorization.oauth2'
TOKEN_URL = 'https://api.paloaltonetworks.com/api/oauth2/RequestToken'
REVOKE_TOKEN_URL = 'https://api.paloaltonetworks.com/api/oauth2/RevokeToken'
APIGW_URL = 'https://apigw-stg4.us.paloaltonetworks.com'
VENDOR = 'panw'
