# no_auth_servers.py
from socketserver import TCPServer, BaseRequestHandler
import threading

class FTPHandler(BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"220 Welcome to Vulnerable FTP\r\n")
        self.request.sendall(b"331 Password required for root\r\n")
        # Принимаем любой пароль
        data = self.request.recv(1024)
        self.request.sendall(b"230 Login successful\r\n")

class TelnetHandler(BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"Welcome to Vulnerable Telnet\r\n")
        self.request.sendall(b"login: ")
        self.request.recv(1024)  # Игнорируем логин
        self.request.sendall(b"password: ")
        self.request.recv(1024)  # Игнорируем пароль
        self.request.sendall(b"Access granted\r\n")

def start_server(port, handler):
    with TCPServer(('0.0.0.0', port), handler) as server:
        print(f"Уязвимый сервер запущен на port {port} (без пароля)")
        server.serve_forever()

# Запуск FTP (port 21) и Telnet (port 23) в отдельных потоках
threading.Thread(target=start_server, args=(21, FTPHandler)).start()
threading.Thread(target=start_server, args=(23, TelnetHandler)).start()