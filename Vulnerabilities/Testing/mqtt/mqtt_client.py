# mqtt_client.py
import socket
import json

def mqtt_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 1883))
    
    # Подписка на топик
    sub_msg = {
        'type': 'subscribe',
        'topic': 'test/topic'
    }
    s.sendall(json.dumps(sub_msg).encode())
    
    # Публикация сообщения
    pub_msg = {
        'type': 'publish',
        'topic': 'test/topic',
        'message': 'Hello MQTT!'
    }
    s.sendall(json.dumps(pub_msg).encode())
    
    # Получение ответа (должно быть то же сообщение)
    data = s.recv(1024)
    print("Получено:", data.decode())
    
    s.close()

mqtt_client()