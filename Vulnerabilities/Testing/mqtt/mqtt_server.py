# simple_mqtt.py
import socket
import json
import threading

class SimpleMQTTServer:
    def __init__(self):
        self.topics = {}
        self.clients = []
        
    def handle_client(self, conn, addr):
        print(f"Новое подключение: {addr}")
        while True:
            try:
                data = conn.recv(1024).decode()
                if not data:
                    break
                    
                message = json.loads(data)
                if message['type'] == 'subscribe':
                    self.topics.setdefault(message['topic'], []).append(conn)
                elif message['type'] == 'publish':
                    for client in self.topics.get(message['topic'], []):
                        try:
                            client.sendall(json.dumps(message).encode())
                        except:
                            pass
            except:
                break
        conn.close()

    def start(self, port=1883):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', port))
            s.listen()
            print(f"Простой MQTT сервер запущен на port {port}")
            
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    server = SimpleMQTTServer()
    server.start()