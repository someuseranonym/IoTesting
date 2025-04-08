# weak_auth_servers.py
from socketserver import TCPServer, BaseRequestHandler
import threading

WEAK_PASSWORDS = ["admin", "password", "123456", "root", "test"]

class HTTPHandler(BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"HTTP/1.1 401 Unauthorized\r\n")
        self.request.sendall(b"WWW-Authenticate: Basic realm=\"Secure Area\"\r\n\r\n")
        data = self.request.recv(1024)
        if b"Authorization: Basic" in data:
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")

class SSHHandler(BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")
        data = self.request.recv(1024)
        if b"password" in data.lower():
            for weak_pass in WEAK_PASSWORDS:
                if weak_pass.encode() in data:
                    self.request.sendall(b"Access granted\n")
                    return
            self.request.sendall(b"Access denied\n")

def start_weak_server(port, handler):
    with TCPServer(('0.0.0.0', port), handler) as server:
        print(f"Сервер со слабыми паролями запущен на port {port}")
        server.serve_forever()

# Запуск HTTP (port 80) и SSH (port 22) в отдельных потоках
threading.Thread(target=start_weak_server, args=(80, HTTPHandler)).start()
threading.Thread(target=start_weak_server, args=(22, SSHHandler)).start()