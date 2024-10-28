from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

# Database file name
DB_FILE = 'totally_not_my_privateKeys.db'

# Host name and server port declaration
hostName = "localhost"
serverPort = 8080

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Save a private key in the database
def save_key(key, exp):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (key, exp))
    conn.commit()
    conn.close()

# Load a key from the database
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
        # print(f"Loaded key: {key_bytes}")  # Debug line to see the key bytes
        return key_bytes  # Return the key as bytes
    return None

# Generate and store keys at the start
def generate_and_store_keys():
    # Generate valid key (1 hour validity)
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # Ensure no encryption
    )
    valid_exp = int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).timestamp())
    save_key(valid_pem, valid_exp)

    # Generate expired key (already expired)
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # Ensure no encryption
    )
    expired_exp = int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).timestamp())
    save_key(expired_pem, expired_exp)

# Class which designates the functions of the server
class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            key_bytes = load_key(expired='expired' in params)
            if key_bytes is None:
                print("No key found in DB.")
                self.send_response(500)
                self.end_headers()
                return

            try:
                private_key = serialization.load_pem_private_key(key_bytes, password=None)
            except Exception as e:
                print(f"Failed to load private key: {e}")
                self.send_response(500)
                self.end_headers()
                return

            headers = {
                "kid": "expiredKID" if 'expired' in params else "goodKID"
            }
            token_payload = {
                "user": "userABC",
                "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            }
            # print(f"Signing JWT with key ID: {headers['kid']}")
            # print(f"Key being used for signing (first 50 bytes): {key_bytes[:50]}")
            # print(f"Signing JWT with payload: {token_payload} using key ID: {headers['kid']}")
            # print("Generating JWT...")
            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
            # print(f"JWT generated: {encoded_jwt}")
            # Return JWT in JSON format
            # After generating the JWT
            #print(f"JWT generated: {encoded_jwt}")
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = {"jwt": encoded_jwt}
            self.wfile.write(bytes(json.dumps(response), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        try:
            if self.path == "/.well-known/jwks.json":
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
                cursor.execute('SELECT key FROM keys WHERE exp > ?', (current_time,))
                rows = cursor.fetchall()

                if not rows:
                    print("No valid keys found in the database.")
                    self.send_response(500)
                    self.end_headers()
                    return

                keys = {"keys": []}

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

                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                print(f"JWKS response: {json.dumps(keys)}")  # Log the JWKS response
                self.wfile.write(bytes(json.dumps(keys), "utf-8"))
                conn.close()
                return
        except Exception as e:
            print(f"Error while handling GET request: {e}")
            self.send_response(500)
            self.end_headers()

        self.send_response(405)
        self.end_headers()

# Utility to convert integer to base64
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Main execution block
if __name__ == "__main__":
    init_db()
    generate_and_store_keys()
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()