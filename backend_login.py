import http.server
import json
import mysql.connector
import hashlib
import re

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Tej@shwini05',
    'database': 'Desi'
}

def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as err:
        print(f"Error connecting to MySQL: {err}")
        return None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_login(username, password):
    errors = {}
    if not username.strip():
        errors['username'] = 'Username cannot be empty.'
    if not password:
        errors['password'] = 'Password cannot be empty.'
    return errors

def handle_login(data):
    username = data.get('username')
    password = data.get('password')
    errors = validate_login(username, password)

    if errors:
        return json.dumps({'success': False, 'errors': errors}).encode('utf-8')

    hashed_password = hash_password(password)

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, hashed_password))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            return json.dumps({'success': True, 'message': 'Login successful'}).encode('utf-8')
        else:
            return json.dumps({'success': False, 'message': 'Invalid username or password'}).encode('utf-8')
    else:
        return json.dumps({'success': False, 'message': 'Database connection error'}).encode('utf-8')

class LoginHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/login':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            response = handle_login(data)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(response)
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == '/login':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            try:
                with open('login.html', 'rb') as file:
                    self.wfile.write(file.read())
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found")
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            try:
                with open('index.html', 'rb') as file:
                    self.wfile.write(file.read())
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"File not found")

if __name__ == '__main__':
    server_address = ('', 8001)
    httpd = http.server.HTTPServer(server_address, LoginHandler)
    print('Starting login server on port 8001...')
    httpd.serve_forever()