from base64 import b64encode

class Config:
    SECRET_KEY = "super_secret_key"
    CLIENT_ID = "3e8e53b18427433fb4b9dbcf3d4ad2ad"
    CLIENT_SECRET = "cef1079fa4644bdf946fb1aa89759e88"
    REDIRECT_URI = "http://127.0.0.1:5000/callback"
    SCOPE = "user-read-recently-played user-top-read"
    AUTHORIZATION = "Basic {}".format(b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode('ascii')).decode('ascii'))
    CACHE_TYPE = "SimpleCache"
    CACHE_DEFAULT_TIMEOUT = 300