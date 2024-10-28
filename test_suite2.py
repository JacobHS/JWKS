import unittest
import jwt
from http.server import HTTPServer
from urllib import request
from threading import Thread
import json
import time
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Assuming the server code is saved as `main.py`
from main import MyServer, hostName, serverPort, DB_FILE

# Setting up unittest
# This allows you to setup test functions that will be timed and recorded for completion or failure
class TestSuite(unittest.TestCase):
     # This is the setup before the test suite is run. This connects us to the JWKS server.
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer((hostName, serverPort), MyServer)
        cls.server_thread = Thread(target=cls.server.serve_forever)
        cls.server_thread.start()
        # Allow the server to start
        time.sleep(1)
        
        # Initialize the database for tests
        cls.init_db()

    # This ends the unittest shuting down connections to the server
    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server_thread.join()
        time.sleep(1)  # Wait for the server thread to fully close

    @classmethod
    def init_db(cls):
        # Setup database for testing
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS keys (key BLOB, exp INTEGER)')
        conn.commit()
        conn.close()

    # Test for the PUT method. Tests for a 405 status meaning that it is not allowed.
    def test_put_method(self):
        req = request.Request(f'http://{hostName}:{serverPort}/', method='PUT')
        with self.assertRaises(request.HTTPError) as context:
            request.urlopen(req)
        self.assertEqual(context.exception.code, 405)

    # Test for the PATCH method. Tests for a 405 status meaning that it is not allowed.
    def test_patch_method(self):
        req = request.Request(f'http://{hostName}:{serverPort}/', method='PATCH')
        with self.assertRaises(request.HTTPError) as context:
            request.urlopen(req)
        self.assertEqual(context.exception.code, 405)

    # Test for the DEL method. Tests for a 405 status meaning that it is not allowed.
    def test_delete_method(self):
        req = request.Request(f'http://{hostName}:{serverPort}/', method='DELETE')
        with self.assertRaises(request.HTTPError) as context:
            request.urlopen(req)
        self.assertEqual(context.exception.code, 405)

    # Test for the HEAD method. Tests for a 405 status meaning that it is not allowed.
    def test_head_method(self):
        req = request.Request(f'http://{hostName}:{serverPort}/', method='HEAD')
        with self.assertRaises(request.HTTPError) as context:
            request.urlopen(req)
        self.assertEqual(context.exception.code, 405)

    # Sends a POST request through /auth and checks for 200 Response. Will also decode the token and make sure data is correct.
    def test_post_auth_valid(self):
        req = request.Request(f'http://{hostName}:{serverPort}/auth', method='POST')
        response = request.urlopen(req)
        self.assertEqual(response.getcode(), 200)
        token = json.loads(response.read().decode('utf-8'))['jwt']
        self.assertTrue(token)

        # Validate the token (decode with public key; adjust key retrieval as needed)
        public_key = self.get_public_key()
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        self.assertEqual(decoded['user'], 'username')

    # Inserts a new expired key into the DB and sends a POST request through /auth for expired tokens and compares
    def test_post_auth_expired(self):
        # First, we need to manually insert an expired key into the database
        self.insert_expired_key()
        
        req = request.Request(f'http://{hostName}:{serverPort}/auth?expired=true', method='POST')
        response = request.urlopen(req)
        self.assertEqual(response.getcode(), 200)
        expired_token = json.loads(response.read().decode('utf-8'))['jwt']
        self.assertTrue(expired_token)

        # Attempt to decode the expired token
        public_key = self.get_public_key(expired=True)
        with self.assertRaises(jwt.ExpiredSignatureError):
            jwt.decode(expired_token, public_key, algorithms=["RS256"])

    # Sends a GET request to the server .well-known/jwks.json endpoint and looks for 200 response.
    # Also validates at least one key is present
    def test_get_jwks(self):
        req = request.Request(f'http://{hostName}:{serverPort}/.well-known/jwks.json', method='GET')
        response = request.urlopen(req)
        self.assertEqual(response.getcode(), 200)
        jwks = json.loads(response.read().decode('utf-8'))
        self.assertIn('keys', jwks)
        self.assertGreater(len(jwks['keys']), 0)

        # Validate the JWK format
        key = jwks['keys'][0]
        self.assertEqual(key['alg'], 'RS256')
        self.assertEqual(key['kty'], 'RSA')

    # Function that inserts an expire key into the DB for the test_post_auth_expired function
    def insert_expired_key(self):
        # Function to insert an expired key for testing
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_pem = expired_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        expired_exp = int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).timestamp())
        cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (expired_pem, expired_exp))
        conn.commit()
        conn.close()

    # Used by both POST tests to get the public keys from the DB for comparison
    def get_public_key(self, expired=False):
        # Function to retrieve public key for decoding JWT
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        condition = 'exp <= ?' if expired else 'exp > ?'
        cursor.execute(f'SELECT key FROM keys WHERE {condition}', (current_time,))
        row = cursor.fetchone()
        conn.close()
        if row:
            private_key = serialization.load_pem_private_key(row[0], password=None)
            return private_key.public_key()  # Return public key for JWT validation
        return None

# If script is executed starts tests.
if __name__ == '__main__':
    unittest.main()