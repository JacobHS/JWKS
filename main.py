from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

# Database file name
DB_FILE = 'totally_not_my_privateKeys.db'

# Host name and server port delaration
hostName = "localhost"
serverPort = 8080

# Initialize SQLite database for JWKS server
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    conn.close()

# Save an RSA private key in the database
def save_key(key, exp):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (key, exp))
    conn.commit()
    conn.close()

# Loads a key from the database
def load_key(expired=False):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    
    if expired:
        cursor.execute('SELECT key FROM keys WHERE exp <= ?', (current_time,))
    else:
        cursor.execute('SELECT key FROM keys WHERE exp > ?', (current_time,))

    row = cursor.fetchone()
    conn.close()
    
    if row:
        key_bytes = row[0]
        return key_bytes  # Return the key as bytes
    return None

# Generate and store keys at the start
def generate_and_store_keys():
    # Generate valid key (1 hour validity)
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        # Ensure no encryption
        encryption_algorithm=serialization.NoEncryption()  
    )
    valid_exp = int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).timestamp())
    save_key(valid_pem, valid_exp)

    # Generate expired key (already expired, 1 hour old)
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        # Ensure no encryption
        encryption_algorithm=serialization.NoEncryption()  
    )
    expired_exp = int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).timestamp())
    save_key(expired_pem, expired_exp)

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

        # Auth check
        if parsed_path.path == "/auth":
            # Loads keys
            key_bytes = load_key(expired='expired' in params)
            if key_bytes is None:
                print("No key found in DB.")
                self.send_response(500)
                self.end_headers()
                return

            # Load private key
            try:
                private_key = serialization.load_pem_private_key(key_bytes, password=None)
            except Exception as e:
                print(f"Failed to load private key: {e}")
                self.send_response(500)
                self.end_headers()
                return

            # Setup JWT Token
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            }
            # Handling of expired tokens
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
            
            # Generate the JWT Token
            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
            
            # Sending Response
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = {"jwt": encoded_jwt}
            self.wfile.write(bytes(json.dumps(response), "utf-8"))
            return
        # Not auth post
        self.send_response(405)
        self.end_headers()
        return

    # Parses a GET request for any /.well-known/jwks.json queries. It will construct a JSON object with the RSA key details. 
    # If the GET request is not for /.well-known/jwks.json it will return 405
    def do_GET(self):
        # Check path
        if self.path == "/.well-known/jwks.json":
            # Connect to sqlite DB
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            # Get Time
            current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
            # Run SQL SELECT statement for valid keys
            cursor.execute('SELECT key FROM keys WHERE exp > ?', (current_time,))
            rows = cursor.fetchall()

            # If no keys are found send 500 error
            if not rows:
                print("No valid keys found in the database.")
                self.send_response(500)
                self.end_headers()
                return

            # Prep key JWKS response
            keys = {"keys": []}

            # Go through all the keys
            for row in rows:
                key_bytes = row[0]
                private_key = serialization.load_pem_private_key(key_bytes, password=None)
                public_key = private_key.public_key()
                numbers = public_key.public_numbers()
                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e),
                })

            # Send all valid keys as JSON
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            conn.close()
            return
        # If path is not correct error
        self.send_response(405)
        self.end_headers()
        return

# Function to convert to base64
def int_to_base64(value):
    # Convert int to hex
    value_hex = format(value, 'x')
    # Ensure even length of hex
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    # Hex ot bytes
    value_bytes = bytes.fromhex(value_hex)
    # Actuall base64 encoding
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    # Return encoded int
    return encoded.decode('utf-8')

# Starts server when code it run. Will run until a keyboard interupt is input, Ctrl+C.
if __name__ == "__main__":
    # Start DB
    init_db()
    # Generate all keys and store all keys to DB
    generate_and_store_keys()
    # Host JWKS Server
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
