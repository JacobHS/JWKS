from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

# Host name and server port delaration
hostName = "localhost"
serverPort = 8080

# Generates a new RSA private key for JWT. A second key in created for expired tokens,
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Converts the private keys into PEM format. These are BASE64 encoded representations.
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Stores private key's value
numbers = private_key.private_numbers()

# Converts ints into a BASE64 encoded string. 
def int_to_base64(value):
    #Convert an integer to a Base64URL-encoded string
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Class which designates the functions of the server
class MyServer(BaseHTTPRequestHandler):
    # If a PUT request is put in it sends a 405 message, Method Not Allowed.
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    # If a PATCH request is put in it sends a 405 message, Method Not Allowed.
    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    # If a DELETE request is put in it sends a 405 message, Method Not Allowed.
    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    # If a HEAD request is put in it sends a 405 message, Method Not Allowed.
    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    # Parses a POST request for any /auth queries with a JWT payload. If the POST request is not for /auth it will return 405.
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    # Parses a GET request for any /.well-known/jwks.json queries. It will construct a JSON object with the RSA key details. 
    # If the GET request is not for /.well-known/jwks.json it will return 405
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

# Starts server when code it run. Will run until a keyboard interupt is input, Ctrl+C.
if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
