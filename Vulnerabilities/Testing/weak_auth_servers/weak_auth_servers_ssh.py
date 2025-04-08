# weak_auth_servers_ssh.py
import socket
import threading
import logging
from time import sleep

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('SSH_Server')

WEAK_PASSWORDS = ["admin", "password", "123456", "root", "test"]

class SimpleSSHServer:
    SSH_BANNER = "SSH-2.0-OpenSSH_7.9\n"
    
    def __init__(self, port=2222):
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False

    def handle_client(self, conn):
        try:
            conn.sendall(self.SSH_BANNER.encode())
            
            # Простая эмуляция SSH - только для тестирования weak auth
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                    
                data_str = data.decode().lower()
                if any(pwd.encode() in data for pwd in WEAK_PASSWORDS):
                    conn.sendall(b"Authentication successful!\n")
                    logger.info(f"Successful login with password in: {data_str[:20]}...")
                    break
                else:
                    conn.sendall(b"Authentication failed.\n")
        except Exception as e:
            logger.error(f"Client error: {e}")
        finally:
            conn.close()

    def start(self):
        try:
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(5)
            self.running = True
            logger.info(f"Simple SSH server started on port {self.port}")
            logger.info(f"Accepting these weak passwords: {WEAK_PASSWORDS}")
            
            while self.running:
                conn, addr = self.socket.accept()
                logger.info(f"New connection from {addr}")
                threading.Thread(target=self.handle_client, args=(conn,)).start()
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.socket.close()

    def stop(self):
        self.running = False
        # Создаем временное подключение чтобы выйти из accept()
        try:
            with socket.socket() as temp_sock:
                temp_sock.connect(('localhost', self.port))
        except:
            pass

if __name__ == "__main__":
    server = SimpleSSHServer(port=2222)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
        print("\nServer stopped")