# ssh_client_test.py
import socket
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('SSH_Test')

def test_ssh_password(password):
    try:
        with socket.socket() as s:
            s.connect(('localhost', 2222))
            banner = s.recv(1024)
            logger.info(f"Server banner: {banner.decode().strip()}")
            
            # Простая имитация SSH-клиента
            s.sendall(f"ssh-connection\nusername:root\npassword:{password}\n".encode())
            response = s.recv(1024).decode()
            
            if "successful" in response.lower():
                logger.info(f"Success! Password worked: {password}")
                return True
            else:
                logger.warning(f"Failed password: {password}")
                return False
    except Exception as e:
        logger.error(f"Connection error: {e}")
        return False

if __name__ == "__main__":
    WEAK_PASSWORDS = ["admin", "password", "123456", "root", "test"]
    
    print("Testing SSH weak passwords...")
    for pwd in WEAK_PASSWORDS:
        if test_ssh_password(pwd):
            break