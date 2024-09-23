import unittest
import jwt
from http.server import HTTPServer
from urllib import request
from threading import Thread
import json
import time

# Assuming the server code is saved as `main .py`
from main import MyServer, hostName, serverPort, pem, expired_pem

# Setting up unittest
# This allows you to setup test functions that will be timed and recorded for completion or failure
class TestSuite(unittest.TestCase):
    # This is the setup before the test suite is run. This connects us to the JWKS server.
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer((hostName,serverPort),MyServer)
        cls.server_thread = Thread(target=cls.server.serve_forever)
        cls.server_thread.start()
        # Allow the server to start
        time.sleep(1)  
    
    # This ends the unittest shuting down connections to the server
    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server_thread.join()

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

    # Tests the /auth endpoint for valid JWT generation by sending a POST request to /auth. Checks for a 200 status meaning it was successful.
    def test_post_auth_valid(self):
        data = request.Request(f'http://{hostName}:{serverPort}/auth', method='POST')
        response = request.urlopen(data)
        self.assertEqual(response.getcode(), 200)
        token = response.read().decode('utf-8')
        self.assertTrue(token)

        # Validate the token using the public key (You can decode it to validate)
        decoded = jwt.decode(token, pem, algorithms=["RS256"])
        self.assertEqual(decoded['user'], 'username')

    # Tests the /auth endpoint for valid JWT generation by sending a POST request to /auth with the expired parameter marked. Checks for a 200 status meaning it was successful.
    def test_post_auth_expired(self):
        data = request.Request(f'http://{hostName}:{serverPort}/auth?expired=true', method='POST')
        response = request.urlopen(data)
        self.assertEqual(response.getcode(), 200)
        expired_token = response.read().decode('utf-8')
        self.assertTrue(expired_token)

        # Attempt to decode the expired token using the appropriate public key
        with self.assertRaises(jwt.ExpiredSignatureError):
            jwt.decode(expired_token, expired_pem, algorithms=["RS256"])

    # Sends a get request to /jwks.json to fetch the JWKS. Checks for a 200 response that it contains the keys array
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

# If script is executed starts tests.
if __name__ == '__main__':
    unittest.main()