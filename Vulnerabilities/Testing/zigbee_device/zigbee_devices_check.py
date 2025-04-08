# zigbee_devices_check.py
import socket
import json
import time

def test_zigbee_device(port, command):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)  # Таймаут 2 секунды
        s.sendto(command.encode() if isinstance(command, str) else command, ('localhost', port))
        
        data, _ = s.recvfrom(1024)
        try:
            return json.loads(data.decode())
        except:
            return data.decode()
    except socket.timeout:
        return "Таймаут: устройство не ответило"
    except Exception as e:
        return f"Ошибка: {str(e)}"

def check_zigbee_vulnerabilities():
    print("="*50)
    print("Начало проверки Zigbee-устройств")
    print("="*50)
    
    # 1. Проверка конфликта PAN ID
    pan1 = test_zigbee_device(5000, "get_pan_id")
    pan2 = test_zigbee_device(5001, "get_pan_id")
    
    if pan1 == pan2:
        print(f"[Уязвимость] Обнаружен конфликт PAN ID: {pan1}")
    else:
        print("[OK] PAN ID устройств различаются")
    
    # 2. Проверка небезопасной передачи ключа
    key_response = test_zigbee_device(5000, "get_key")
    if isinstance(key_response, dict) and "key" in key_response:
        print(f"[Уязвимость] Устройство на порту 5000 передало ключ в открытом виде: {key_response['key']}")
    else:
        print("[OK] Устройство на порту 5000 не передает ключ открыто")
    
    # 3. Проверка ключа по умолчанию
    key_response = test_zigbee_device(5001, "get_key")
    if isinstance(key_response, dict) and key_response.get("key") == "DEFAULT_KEY":
        print("[Уязвимость] Устройство на порту 5001 использует ключ по умолчанию")
    else:
        print("[OK] Устройство на порту 5001 не использует ключ по умолчанию")
    
    print("="*50)
    print("Проверка завершена")
    print("="*50)

if __name__ == "__main__":
    # Сначала проверяем доступность устройств
    print("Проверка связи с устройствами...")
    print("Устройство 5000:", test_zigbee_device(5000, "ping"))
    print("Устройство 5001:", test_zigbee_device(5001, "ping"))
    
    # Затем запускаем полную проверку
    check_zigbee_vulnerabilities()
    input("Нажмите Enter для выхода...")