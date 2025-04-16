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

def validate_registration(username, password, email, phone):
    errors = {}
    if not username.strip():
        errors['username'] = 'Username cannot be empty.'
    if not password:
        errors['password'] = 'Password cannot be empty.'
    elif len(password) < 8:
        errors['password'] = 'Password must be at least 8 characters long.'
    elif not re.search(r'[A-Z]', password):
        errors['password'] = 'Password must contain at least one uppercase letter.'
    elif not re.search(r'[a-z]', password):
        errors['password'] = 'Password must contain at least one lowercase letter.'
    elif not re.search(r'[0-9]', password):
        errors['password'] = 'Password must contain at least one digit.'
    elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors['password'] = 'Password must contain at least one special character.'
    if not email:
        errors['email'] = 'Email cannot be empty.'
    elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        errors['email'] = 'Invalid email address.'
    if not phone:
        errors['phone'] = 'Phone number cannot be empty.'
    elif not re.match(r"^(\+91[\-\s]?)?[6789]\d{9}$", phone):
        errors['phone'] = 'Invalid Indian phone number.'
    return errors

def handle_register(data):
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    phone = data.get('phone')
    errors = validate_registration(username, password, email, phone)

    if errors:
        return json.dumps({'success': False, 'errors': errors}).encode('utf-8')

    hashed_password = hash_password(password)

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            query = "INSERT INTO users (username, password, email, phone) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (username, hashed_password, email, phone))
            conn.commit()
            return json.dumps({'success': True, 'message': 'Registration successful!'}).encode('utf-8')
        except mysql.connector.IntegrityError as e:
            if 'username' in str(e):
                return json.dumps({'success': False, 'message': 'Username already exists'}).encode('utf-8')
            elif 'email' in str(e):
                return json.dumps({'success': False, 'message': 'Email already exists'}).encode('utf-8')
            else:
                return json.dumps({'success': False, 'message': f'Database error: {e}'}).encode('utf-8')
        except mysql.connector.Error as e:
            return json.dumps({'success': False, 'message': f'Database error: {e}'}).encode('utf-8')
        finally:
            cursor.close()
            conn.close()
    else:
        return json.dumps({'success': False, 'message': 'Database connection error'}).encode('utf-8')

class RegisterHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/register':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            response = handle_register(data)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(response)
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == '/register':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            try:
                with open('register.html', 'rb') as file:
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
    server_address = ('', 8002)
    httpd = http.server.HTTPServer(server_address, RegisterHandler)
    print('Starting registration server on port 8002...')
    httpd.serve_forever()