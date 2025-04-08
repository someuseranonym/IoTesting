# weak_auth_servers_http.py
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading
import base64

WEAK_PASSWORDS = ["admin", "password", "123456", "root", "test"]

class WeakHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if 'Authorization' not in self.headers:
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Test Realm"')
            self.end_headers()
            self.wfile.write(b'Authentication required')
            return
        
        auth_header = self.headers['Authorization']
        if not auth_header.startswith('Basic '):
            self.send_response(401)
            self.end_headers()
            return
            
        auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
        username, password = auth_decoded.split(':', 1)
        
        if password in WEAK_PASSWORDS:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f'Access granted with password: {password}'.encode())
        else:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'Access denied - password not in weak list')

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Многопоточный HTTP-сервер"""

def run_server():
    server = ThreadedHTTPServer(('localhost', 80), WeakHTTPHandler)
    print("HTTP сервер со слабыми паролями запущен на http://localhost:80")
    print(f"Допустимые пароли: {', '.join(WEAK_PASSWORDS)}")
    server.serve_forever()

if __name__ == "__main__":
    run_server()