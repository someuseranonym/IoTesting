# smtp_server.py
import socket
import threading

users = ["admin", "user", "root", "test"]

def handle_client(conn):
    conn.send(b"220 Vulnerable SMTP Server\r\n")
    try:
        while True:
            data = conn.recv(1024).decode().strip()
            if not data:
                break
                
            if data.upper().startswith("VRFY "):
                username = data[5:].strip()
                if username in users:
                    conn.send(f"250 {username} exists\r\n".encode())
                else:
                    conn.send(b"550 User unknown\r\n")
            else:
                conn.send(b"250 OK\r\n")
    finally:
        conn.close()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 25))
        s.listen()
        print("Уязвимый SMTP сервер запущен на port 25")
        
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn,)).start()

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("\nСервер остановлен")