# zigbee_devices.py
import socket
import json
import threading

class VulnerableZigbeeDevice:
    def __init__(self, pan_id, port, insecure=False, default_key=False):
        self.pan_id = pan_id
        self.port = port
        self.insecure = insecure
        self.default_key = default_key
        self.key = "DEFAULT_KEY" if default_key else "SECURE_KEY_123"
        
    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('0.0.0.0', self.port))
            print(f"Zigbee устройство запущено на port {self.port} | PAN ID: {self.pan_id}")
            
            while True:
                data, addr = s.recvfrom(1024)
                if data == b"get_key" and self.insecure:
                    response = {"pan_id": self.pan_id, "key": self.key}
                    s.sendto(json.dumps(response).encode(), addr)
                elif data == b"get_pan_id":
                    s.sendto(str(self.pan_id).encode(), addr)
                elif data == b"ping":
                    s.sendto(b"pong", addr)

# Устройство 1: с одинаковым PAN ID и небезопасной передачей ключа
device1 = VulnerableZigbeeDevice(1234, 5000, insecure=True)
# Устройство 2: с одинаковым PAN ID и ключом по умолчанию
device2 = VulnerableZigbeeDevice(1234, 5001, default_key=True)

# Запуск в отдельных потоках
threading.Thread(target=device1.start).start()
threading.Thread(target=device2.start).start()