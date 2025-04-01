import ftplib
import telnetlib
import pyshark
#from killerbee import KillerBee
import paho.mqtt.client as mqtt
import subprocess
import logging
import time
import argparse

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Функция для проверки FTP на анонимное подключение
def check_ftp_anonymous(ip):
    """
    Проверяет, разрешено ли анонимное подключение к FTP-серверу.
    :param ip: IP-адрес устройства
    :return: True, если анонимное подключение разрешено, иначе False
    """
    try:
        with ftplib.FTP(ip) as ftp:  # Используем контекстный менеджер для автоматического закрытия соединения
            ftp.login()  # Попытка анонимного входа
            return True
    except ftplib.error_perm:
        return False

# Функция для проверки FTP на незашифрованную передачу данных
def check_ftp_unencrypted(ip, interface='eth0'):
    """
    Проверяет, передаются ли логин и пароль FTP в незашифрованном виде.
    :param ip: IP-адрес устройства
    :param interface: Сетевой интерфейс для захвата трафика (по умолчанию 'eth0')
    :return: True, если данные передаются в открытом виде, иначе False
    """
    try:
        capture = pyshark.LiveCapture(interface=interface, display_filter='ftp')  # Захват FTP-трафика
        capture.sniff(timeout=10)  # Захват трафика в течение 10 секунд
        for packet in capture:
            if 'USER' in str(packet) and 'PASS' in str(packet):  # Проверка на передачу логина и пароля
                return True
        return False
    except Exception as e:
        logging.error(f"Ошибка при захвате FTP трафика: {e}")
        return False

# Функция для проверки MQTT на возможность входа без пароля
def check_mqtt_anonymous(ip):
    """
    Проверяет, разрешено ли подключение к MQTT-брокеру без пароля.
    :param ip: IP-адрес устройства
    :return: True, если подключение без пароля разрешено, иначе False
    """
    client = mqtt.Client()
    try:
        client.connect(ip, 1883, 60)  # Подключение к MQTT-брокеру
        return client.is_connected()
    finally:
        client.disconnect()  # Закрытие соединения

# Функция для проверки MQTT на возможность публикации и подписки
def check_mqtt_publish_subscribe(ip):
    """
    Проверяет, возможно ли публиковать сообщения и подписываться на топики в MQTT.
    :param ip: IP-адрес устройства
    :return: True, если публикация и подписка возможны, иначе False
    """
    received_message = False

    def on_message(client, userdata, message):
        """Обработчик сообщений MQTT."""
        nonlocal received_message
        if message.payload.decode() == "Test Message":
            received_message = True

    client = mqtt.Client()
    try:
        client.connect(ip, 1883, 60)  # Подключение к MQTT-брокеру
        client.loop_start()  # Запуск цикла обработки сообщений
        client.subscribe("test/topic")  # Подписка на топик
        client.publish("test/topic", "Test Message")  # Публикация сообщения
        client.on_message = on_message  # Установка обработчика сообщений
        time.sleep(2)  # Ожидание доставки сообщения
        client.loop_stop()  # Остановка цикла обработки сообщений
        return received_message
    finally:
        client.disconnect()  # Закрытие соединения

# Функция для проверки Telnet на анонимное подключение
def check_telnet_anonymous(ip):
    """
    Проверяет, разрешено ли анонимное подключение к Telnet-серверу.
    :param ip: IP-адрес устройства
    :return: True, если анонимное подключение разрешено, иначе False
    """
    try:
        with telnetlib.Telnet(ip) as telnet:  # Используем контекстный менеджер для автоматического закрытия соединения
            telnet.read_until(b"login: ")  # Ожидаем запроса на логин
            telnet.write(b"\n")  # Пытаемся подключиться без пароля
            return True
    except Exception as e:
        logging.error(f"Ошибка при проверке Telnet на анонимное подключение: {e}")
        return False

# Функция для проверки Telnet на незашифрованную передачу данных
def check_telnet_unencrypted(ip, interface='eth0'):
    """
    Проверяет, передаются ли логин и пароль Telnet в незашифрованном виде.
    :param ip: IP-адрес устройства
    :param interface: Сетевой интерфейс для захвата трафика (по умолчанию 'eth0')
    :return: True, если данные передаются в открытом виде, иначе False
    """
    try:
        capture = pyshark.LiveCapture(interface=interface, display_filter='telnet')  # Захват Telnet-трафика
        capture.sniff(timeout=10)  # Захват трафика в течение 10 секунд
        for packet in capture:
            if 'USER' in str(packet) and 'PASS' in str(packet):  # Проверка на передачу логина и пароля
                return True
        return False
    except Exception as e:
        logging.error(f"Ошибка при захвате Telnet трафика: {e}")
        return False

# Функция для проверки ZigBee на небезопасную передачу ключей
def check_zigbee_insecure_keys(pcap_file):
    """
    Проверяет, передаются ли ключи ZigBee в незашифрованном виде.
    :param pcap_file: Путь к файлу с захваченным трафиком ZigBee
    :return: True, если ключи передаются в открытом виде, иначе False
    """
    kb = KillerBee()
    kb.load_file(pcap_file)  # Загрузка файла с трафиком
    for packet in kb.packets:
        if packet.is_aps() and packet.aps_command == 0x05:  # Проверка APS-команды Transport Key
            if packet.payload and b'\x00' in packet.payload:  # Проверка на открытый ключ
                return True
    return False

# Функция для проверки ZigBee на использование link key по умолчанию
def check_zigbee_default_link_key(pcap_file):
    """
    Проверяет, используется ли ключ ZigBee по умолчанию.
    :param pcap_file: Путь к файлу с захваченным трафиком ZigBee
    :return: True, если используется ключ по умолчанию, иначе False
    """
    kb = KillerBee()
    kb.load_file(pcap_file)  # Загрузка файла с трафиком
    for packet in kb.packets:
        if packet.is_aps() and b'\x5A\x69\x67\x42\x65\x65\x41\x6C\x6C\x69\x61\x6E\x63\x65\x30\x39' in packet.payload:
            return True
    return False

# Функция для проверки ZigBee на конфликт PAN ID
def check_zigbee_pan_conflict(pcap_file):
    """
    Проверяет, есть ли конфликт PAN ID в сети ZigBee.
    :param pcap_file: Путь к файлу с захваченным трафиком ZigBee
    :return: True, если обнаружен конфликт, иначе False
    """
    kb = KillerBee()
    kb.load_file(pcap_file)  # Загрузка файла с трафиком
    pan_ids = set()
    for packet in kb.packets:
        if packet.is_beacon():  # Проверка на beacon-фреймы
            pan_id = packet.pan_id
            if pan_id in pan_ids:
                return True  # Обнаружен конфликт PAN ID
            pan_ids.add(pan_id)
    return False

# Функция для проверки SMTP на спуфинг
def check_smtp_spoofing(ip):
    """
    Проверяет, возможно ли спуфинг пользователя через SMTP.
    :param ip: IP-адрес устройства
    :return: True, если спуфинг возможен, иначе False
    """
    try:
        result = subprocess.run(['smtp-user-enum', '-M', 'VRFY', '-t', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            logging.error(f"Утилита smtp-user-enum завершилась с ошибкой: {result.stderr.decode()}")
            return False
        return "No such user" not in result.stdout.decode()
    except FileNotFoundError:
        logging.error("Утилита smtp-user-enum не найдена. Установите её для проверки SMTP.")
        return False
    except Exception as e:
        logging.error(f"Ошибка при проверке SMTP: {e}")
        return False

# Главная функция для проверки уязвимостей
def check_vulnerabilities(ip, mac, pcap_file=None):
    """
    Проверяет устройство на наличие уязвимостей.
    :param ip: IP-адрес устройства
    :param mac: MAC-адрес устройства
    :param pcap_file: Путь к файлу с захваченным трафиком ZigBee (опционально)
    :return: Строка с результатами проверки
    """
    vulnerabilities = []
    logging.info(f"Начало проверки устройства с IP {ip} (MAC: {mac})")

    try:
        # Проверки для FTP
        logging.info("Проверка FTP на анонимное подключение...")
        if check_ftp_anonymous(ip):
            vulnerabilities.append('FTP: Анонимное подключение разрешено')
        logging.info("Проверка FTP на незашифрованную передачу данных...")
        if check_ftp_unencrypted(ip):
            vulnerabilities.append('FTP: Логин/пароль передаются в незашифрованном виде')

        # Проверки для MQTT
        logging.info("Проверка MQTT на подключение без пароля...")
        if check_mqtt_anonymous(ip):
            vulnerabilities.append('MQTT: Подключение без пароля разрешено')
        logging.info("Проверка MQTT на публикацию и подписку...")
        if check_mqtt_publish_subscribe(ip):
            vulnerabilities.append('MQTT: Возможность публикации и подписки на топики')

        # Проверки для Telnet
        logging.info("Проверка Telnet на анонимное подключение...")
        if check_telnet_anonymous(ip):
            vulnerabilities.append('Telnet: Анонимное подключение разрешено')
        logging.info("Проверка Telnet на незашифрованную передачу данных...")
        if check_telnet_unencrypted(ip):
            vulnerabilities.append('Telnet: Логин/пароль передаются в незашифрованном виде')

        # Проверки для ZigBee
        '''if pcap_file:
            logging.info("Проверка ZigBee на небезопасную передачу ключей...")
            if check_zigbee_insecure_keys(pcap_file):
                vulnerabilities.append('ZigBee: Небезопасная передача ключей')
            logging.info("Проверка ZigBee на использование link key по умолчанию...")
            if check_zigbee_default_link_key(pcap_file):
                vulnerabilities.append('ZigBee: Используется link key по умолчанию')
            logging.info("Проверка ZigBee на конфликт PAN ID...")
            if check_zigbee_pan_conflict(pcap_file):
                vulnerabilities.append('ZigBee: Конфликт PAN ID')'''

    except Exception as e:
        logging.error(f"Ошибка при проверке уязвимостей: {e}")

    # Вывод уязвимостей
    if vulnerabilities:
        logging.info(f"Найдены уязвимости на устройстве с IP {ip} (MAC: {mac}):")
        for vuln in vulnerabilities:
            logging.info(vuln)
        return f"Уязвимости на устройстве с IP {ip} (MAC: {mac}):\n" + "\n".join(vulnerabilities)
    else:
        logging.info(f"Устройство с IP {ip} (MAC: {mac}) не имеет известных уязвимостей")
        return f"Устройство с IP {ip} (MAC: {mac}) не имеет известных уязвимостей"
result = check_vulnerabilities(ip, mac)
print(result)