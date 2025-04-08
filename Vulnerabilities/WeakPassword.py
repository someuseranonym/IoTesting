import asyncio
import ftplib
import socket
import telnetlib
import time

from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
import requests
from requests.auth import HTTPBasicAuth
import socket
import ssl
import requests
from requests.auth import HTTPBasicAuth
import subprocess
import warnings
from urllib3.exceptions import InsecureRequestWarning
import requests
from pysnmp.entity.engine import SnmpEngine
from pysnmp.hlapi.v3arch import ContextData, UdpTransportTarget, CommunityData
from pysnmp.smi.rfc1902 import ObjectType, ObjectIdentity
from requests.auth import HTTPBasicAuth

from Vulnerabilities.Vulnerability import *
from TypeGetter import *
import paramiko
import argparse
import paho.mqtt.client as mqtt
from socket import socket, SOCK_DGRAM, AF_INET, timeout
from random import randint
from time import sleep
import optparse, sys, os
from subprocess import Popen, PIPE
import threading
import signal
from scapy.all import *
from pysnmp.hlapi import *
import sys
import argparse
from tqdm import tqdm
from functools import partial
import tqdm.notebook as tq

import socket


def check_port(ip_address, port):
    """
    Синхронно проверяет, открыт ли порт на заданном IP-адресе.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Таймаут в секундах

        # Попытка установить соединение
        sock.connect((ip_address, port))

        sock.close()
        return True  # Порт открыт
    except (socket.timeout, socket.error):
        return False  # Порт закрыт или ошибка соединения


def brute_force_ssh(device, usernames, passwords):
    result = check_port(device['ip'], 22)
    if not result:
        print('port 22 closed')
        return False
    print('bruteforce ssh')
    for username in usernames:
        for password in passwords:
            try:
                time.sleep(0.2)
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(device['ip'], port=22, username=username, password=password, timeout=5)

                print(f"[+] Успех! Username: {username}, Пароль: {password}")
                ssh_client.close()
                return True
            except paramiko.AuthenticationException:
                # print(f"[-] Неудачная попытка: Username: {username}, Пароль: {password}")
                pass
            except Exception as e:
                print(f"[!] Ошибка: {e}")
                return

    print("[-] Учетные данные не найдены в заданных списках.")

def check_ssl(target_ip, port):
        """Проверка SSL-сертификата"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((target_ip, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                    cert = ssock.getpeercert()
                    print(f"\n🔐 SSL-сертификат на порту {port}:")
                    print(f" - Субъект: {dict(x[0] for x in cert['subject'])}")
                    print(f" - Действителен до: {cert['notAfter']}")
                    print(f" - Издатель: {dict(x[0] for x in cert['issuer'])}")
                    return True
        except Exception as e:
            print(f"⚠️ Ошибка SSL на порту {port}: {str(e)}")
            return False
def check_https_vulnerabilities(target_ip, username, password):
        """Проверка уязвимостей HTTPS"""
        print(f"\n🔍 Проверка HTTPS на {target_ip}...")
        SSL_PORTS = [443, 8443, 9443]
        for port in SSL_PORTS:
            try:
                url = f"https://{target_ip}:{port}"
                print(f"\nПроверка {url}...")

                # Проверка доступности
                response = requests.get(url,
                                        auth=HTTPBasicAuth(username, password),
                                        verify=False,
                                        timeout=3)

                if response.status_code == 200:
                    print(f"⚠️ HTTPS-интерфейс доступен на порту {port}")
                    check_ssl(target_ip, port)

                    # Дополнительные проверки
                    tests = [
                        ("Конфигурация", "/system-config.ini"),
                        ("Статус", "/cgi-bin/status"),
                        ("Обновление", "/firmware-upgrade")
                    ]

                    for test_name, path in tests:
                        try:
                            test_url = f"{url}{path}"
                            resp = requests.get(test_url, verify=False, timeout=2)
                            if resp.status_code == 200:
                                print(f"   ‼️ Доступен потенциально опасный путь: {path}")
                        except:
                            continue
            except Exception as e:
                print(f"   {str(e)}")
                continue
def check_default_credentials(ip, username, password):
    """Проверка стандартных учетных данных"""
    print("\n🔐 Проверка стандартных паролей...")
    urls_to_check = [
        f"http://{ip}/",
        f"http://{ip}/cgi-bin/userConfig.cgi",
        f"http://{ip}/config.html"
    ]

    for url in urls_to_check:
        try:
            response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=3)
            print(response.text)
            if response.status_code == 200:
                print(f"⚠️ Уязвимость: стандартный пароль работает на {url}", username, password)
                check_https_vulnerabilities(ip, username, password)

                return True
        except:
            continue

    print("✅ Стандартные пароли не работают (или веб-интерфейс недоступен)")
    return False

def brute_force_http(device, usernames, passwords):
    """
    Выполняет брутфорс HTTP-аутентификации, перебирая имена пользователей и пароли.
    """
    print('http bruteforce')
    i = 1

    for username in usernames:
        for password in passwords:
            res = check_default_credentials(device['ip'], username, password)
            if res:
                print('weak password', username, password, device['ip'])

                return


def brute_force_snmp(wordlist, snmp_version, ip, port, timeout=1):
    v_arg = 1 if snmp_version == '2c' else 0  # 1 for SNMPv2c, 0 for v1

    print(f'Starting SNMPv{snmp_version} bruteforce on {ip}:{port}')

    with open(wordlist, 'r') as in_file:
        communities = [line.strip() for line in in_file if line.strip()]

    for com in tqdm(communities, desc="Testing communities"):
        time.sleep(0.2)  # Чтобы не перегружать устройство

        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(com, mpModel=v_arg),
                UdpTransportTarget((ip, port), timeout=timeout, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr как OID
            )
        )

        # Обработка ответа
        if errorIndication:
            tqdm.write(f"'{com}': Error - {errorIndication}")
            continue
        elif errorStatus:
            tqdm.write(f"'{com}': Auth failed - {errorStatus.prettyPrint()}")
            continue

        # Успешный ответ
        tqdm.write(f"\n[+] Found community: '{com}'")
        for varBind in varBinds:
            tqdm.write(f"Response: {' = '.join([x.prettyPrint() for x in varBind])}")
        return com  # Возвращаем найденное community

    print("\n[!] No valid communities found")
    return None


def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))


def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))


def brute_force_mqtt(device, port, usernames, passwords):
    try:
        client = mqtt.Client()
        client.on_connect = on_connect
        client.on_message = on_message
        client.connect(device['ip'], port)
        client.connect(device['ip'], port)
        print('mqtt bruteforce')
        for username in usernames:
            for password in passwords:
                time.sleep(0.2)
                password = password.strip()
                rc = client.username_pw_set(username, password)
                if rc == mqtt.MQTT_ERR_SUCCESS:
                    print("Login succeeded with username, password: ", username, password)
                    break
        print('no passwords')
    except Exception as e:
        print('mqtt', e)


def tcp_syn_scan(ip, port, timeout=5):
    """Сканирует указанный IP-адрес и порт с помощью TCP SYN."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0  # 0 означает, что порт открыт
    except socket.gaierror:
        print(f"Hostname resolution failed for {ip}")
        return False
    except Exception as e:
        # print(f"TCP SYN Scan Error for {ip}:{port} - {e}") #Suppress noise
        return False


def check_telnet_credentials(ip, port, usernames, passwords, timeout=5):
    """
    Проверяет Telnet-устройство на открытую передачу логина/пароля, используя переданные
    default_logins - список кортежей (username, password) для тестирования.
    """
    print('telnet testing ')
    if not tcp_syn_scan(ip, port, timeout):
        print('telnet port is closed')
        return " telnet Port is closed"

    try:
        tn = telnetlib.Telnet(ip, port, timeout=timeout)

        # Try login, then read the prompt
        try:
            tn.read_until(b"ogin:", timeout=timeout)  # Check login prompt
            # Test default credentials
            i = 0
            for username in usernames:
                for password in passwords:
                    tn.write((username + "\n").encode())
                    time.sleep(0.2)
                    tn.read_until(b"assword:", timeout=timeout)
                    tn.write((password + "\n").encode())

                    # Check for success
                    time.sleep(0.2)  # Give it some time to respond
                    response = tn.read_all().decode(errors='ignore')
                    if i < 6:
                        print(response)
                    if "Login incorrect" not in response and "Invalid password" not in response and "Incorrect" not in response and "denied" not in response:
                        print(f"  Telnet: Login successful with {username}:{password}")
                        tn.close()
                        return f"Vulnerable (Telnet, {username}:{password})"
                    i+=1
        except Exception as e:
            print(f"Telnet Login Exception: {e}")
            tn.close()
            return "Login Failure"
        tn.close()  # Clean up the connection
        return "Likely not vulnerable (Telnet, default credentials)"


    except socket.timeout:
        return "Timeout during Telnet check"
    except ConnectionRefusedError:
        return "Connection refused during Telnet check"
    except Exception as e:
        return f"Telnet check error: {e}"


def check_ftp_credentials(ip, port, usernames, passwords, timeout=5):
    """
    Проверяет FTP-устройство на открытую передачу логина/пароля, используя переданные
    default_logins - список кортежей (username, password) для тестирования.
    """
    if not tcp_syn_scan(ip, port, timeout):
        print("Port is closed")
        return False

    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout)  # Connect before login
        print('ftp testing ')
        # Try anonymous login first
        try:
            ftp.login()
            print("  FTP: Anonymous login successful.")
            ftp.quit()
            return "Vulnerable (FTP, anonymous login)"
        except ftplib.error_perm as e:  # Check for non-230 errors (e.g. 530)
            if "530" in str(e):
                print("  FTP: Anonymous login refused")
            else:
                print(f"  FTP: Anonymous login error: {e}")  # Other errors in non-anonymous login

        # Test default credentials
        for username in usernames:
            for password in passwords:
                time.sleep(0.2)
                try:
                    ftp.connect(ip, port, timeout)  # Reconnect each time to restart auth
                    ftp.login(username, password)
                    print(f"  FTP: Login successful with: {username}:{password}")
                    ftp.quit()
                    return f"Vulnerable (FTP, {username}:{password})"
                except ftplib.error_perm as e:  # Check for non-230 errors (e.g. 530)
                    pass
                except Exception as e:
                    print(f"FTP login error: {e}")

        ftp.quit()  # Clean up
        return "Likely not vulnerable (FTP, default credentials)"


    except socket.timeout:
        return "Timeout during FTP check"
    except ConnectionRefusedError:
        return "Connection refused during FTP check"
    except ftplib.all_errors as e:  # Catch all ftplib errors for the initial connect
        return f"FTP connection error: {e}"  # Return error if it can't connect to FTP Server

    except Exception as e:
        return f"FTP check error: {e}"


def check_default_credentials2(ip, username, password):
    """Проверка учетных данных с подробным анализом ответа"""
    print(f"\n🔐 Проверка учетных данных на {ip}...")
    print(f"Используемые credentials: {username}:{password}")

    urls_to_check = [
        f"http://{ip}/",
        f"http://{ip}/cgi-bin/userConfig.cgi",
        f"http://{ip}/config.html",
        f"http://{ip}/cgi-bin/param.cgi",
        f"http://{ip}/cgi-bin/viewer/video.jpg",
        f"http://{ip}/video.mjpg",
        f"http://{ip}/snapshot.jpg"
    ]

    success_urls = []

    for url in urls_to_check:
        try:
            print(f"\nПроверяем URL: {url}")

            # Неаутентифицированный запрос
            unauth_response = requests.get(url, timeout=5, verify=False)
            print(f"Код ответа без аутентификации: {unauth_response.status_code}")
            print(f"Длина ответа: {len(unauth_response.content)} байт")

            # Аутентифицированный запрос
            auth_response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=5, verify=False)
            print(f"Код ответа с аутентификацией: {auth_response.status_code}")
            print(f"Длина ответа: {len(auth_response.content)} байт")

            # Анализ ответов
            if auth_response.status_code == 200:
                # Критерий 1: Изменение кода состояния
                if unauth_response.status_code == 401 and auth_response.status_code == 200:
                    print("⚡ Обнаружено: 401 -> 200 при аутентификации")
                    success_urls.append(url)
                    continue

                # Критерий 2: Анализ содержимого
                content = auth_response.text.lower() if auth_response.text else ""
                if ("login" not in content and
                        "password" not in content and
                        "unauthorized" not in content):
                    print("⚡ Обнаружено: нет ключевых слов аутентификации в ответе")
                    success_urls.append(url)
                    continue

                # Критерий 3: Размер ответа
                if len(auth_response.content) > len(unauth_response.content) + 500:
                    print("⚡ Обнаружено: значительное увеличение размера ответа")
                    success_urls.append(url)
                    continue

                # Критерий 4: Проверка изображений
                if 'image' in auth_response.headers.get('Content-Type', ''):
                    print("⚡ Обнаружено: получено изображение после аутентификации")
                    success_urls.append(url)
                    continue

        except requests.exceptions.RequestException as e:
            print(f"Ошибка при запросе: {str(e)}")
            continue

    if success_urls:
        print("\n⚠️ Уязвимость: следующие URL доступны с указанными учетными данными:")
        for url in success_urls:
            print(f"- {url}")
        return True
    else:
        print("\n✅ Учетные данные не дали доступа к проверяемым URL")
        return False
class WeakPassword(Vulnerability):
    def __init__(self):
        """
        Инициализация объекта.
        """
        super().__init__()  # Вызов конструктора базового класса
        self.name = "Слабый пароль"
        self.desc = "Обнаружен слабый пароль, который легко подобрать."
        self.threats = ("Злоумышленник получит полный контроль над устройством. "
                        "Это означает, что он может изменять настройки, управлять функциями устройства;"
                        "получить доступ к конфиденциальной информации, собираемой устройством. "
                        "Например, он может просматривать видео с камер видеонаблюдения, получать данные с датчиков;"
                        "Использовать устройство для распространения вредоносного ПО на другие устройства в локальной сети.")
        self.methods = ('''

    Замените пароль на сложный:

        Длина: от 12 символов.

        Состав: буквы (A-Z, a-z), цифры (0-9), спецсимволы (!@#$%^&*).

        Пример: МойДом#2024! (легко запомнить, но сложно взломать).

    Отключите ненужные сервисы (если не используете FTP, Telnet, SNMP — выключите их).

    Обновите прошивку/ПО — в новых версиях часто закрывают уязвимости.

🔹 Для компьютеров и серверов (Windows/macOS/Linux)
SSH (если используете):

    Смените пароль:
    bash
    Copy

    passwd

    Отключите вход по паролю (только по ключу):

        Создайте SSH-ключ:
        bash
        Copy

        ssh-keygen -t ed25519

        Скопируйте его на сервер:
        bash
        Copy

        ssh-copy-id user@ваш_IP

        Отключите парольную аутентификацию в /etc/ssh/sshd_config:
        ini
        Copy

        PasswordAuthentication no

FTP (если используете):

    Отключите анонимный доступ (в настройках FTP-сервера).

    Измените пароль пользователя:
    bash
    Copy

    sudo passwd ftp_user

🔹 Для роутеров, камер и IoT-устройств

    Зайдите в веб-интерфейс (обычно через http://192.168.1.1).

    Найдите раздел "Пароль" или "Безопасность".

    Замените пароль администратора.

    Отключите:

        Telnet (если есть)

        SNMP (если не используете)

        Гостевой доступ (если не нужен)

🔹 Для MQTT (умные дома, датчики)

    Включите пароль в настройках брокера (например, Mosquitto).

    Запретите анонимный доступ:
    ini
    Copy

    allow_anonymous false
    password_file /etc/mosquitto/passwd

🛡️ 3. Дополнительная защита

    Используйте менеджер паролей (KeePass, Bitwarden) для хранения сложных паролей.

    Включите двухфакторную аутентификацию (2FA), если устройство поддерживает.

    Регулярно проверяйте обновления для устройств.

🚨 Что делать, если устройство уже взломано?

    Отключите его от интернета.

    Сбросьте настройки до заводских (кнопка Reset на роутерах/камерах).

    Установите новый пароль перед повторным подключением.''')

    def check_for_device(self, device, usernames, passwords):
        print('check', device['mac'], device['type'])
        snmp_path = 'Vulnerabilities/WordLists/snmp_comms.txt'
        if device['type'] in [DeviceType.light_switch, DeviceType.Lamp, DeviceType.Counter, DeviceType.Socket]:
            brute_force_http(device, usernames, passwords)
            brute_force_mqtt(device, 1883, usernames, passwords)
            check_ftp_credentials(device['ip'], 21, usernames, passwords)
            check_telnet_credentials(device['ip'], 23, usernames, passwords)
        match device['type']:
            case DeviceType.Camera:
                brute_force_ssh(device, usernames, passwords)
                check_default_credentials2(device['ip'], 'admin', 'admin')
                check_default_credentials2(device['ip'], 'user', '1')
                #brute_force_http(device, usernames, passwords)
                brute_force_snmp(snmp_path, '1', device['ip'], 22, 2)
                brute_force_snmp(snmp_path, '2c', device['ip'], 22, 2)
            case DeviceType.Printer:
                brute_force_http(device, usernames, passwords)
                brute_force_snmp(snmp_path, '1', device['ip'], 22, 2)
                brute_force_snmp(snmp_path, '2c', device['ip'], 22, 2)
            case DeviceType.Thermostat:
                brute_force_ssh(device, usernames, passwords)
                brute_force_http(device,  usernames, passwords)
                brute_force_mqtt(device, 1883, usernames, passwords)
            case DeviceType.Sensor:
                brute_force_http(device, usernames, passwords)
                brute_force_mqtt(device, 1883, usernames, passwords)
                brute_force_snmp(snmp_path,'1', device['ip'], 22, 2)
                brute_force_snmp(snmp_path,'2c', device['ip'], 22, 2)
            case _:  # Default case (wildcard pattern)
                pass

    def check(self, devices):
        username_file = '/home/mint/PycharmProjects/IoTesting/Vulnerabilities/WordLists/usernames.txt'
        passwords_file ='/home/mint/PycharmProjects/IoTesting/Vulnerabilities/WordLists/rockyou.txt'
        usernames = []
        passwords = []
        try:
            with open(username_file, 'r') as f:
                usernames1 = [line.strip() for line in f]
                for i in usernames1:
                    usernames.append(i)
            with open(passwords_file, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords1 = [line.strip() for line in f]
                    for i in passwords1:
                        passwords.append(i)
        except FileNotFoundError as e:
            print(f"Ошибка: Файл не найден: {e}")
            return
        vulnerable_devices = {}
        print(devices)
        for i in devices:
            if i['type'] != DeviceType.Skip:
                print('device', i['ip'], i['type'])
                cur = self.check_for_device(i, usernames, passwords)
                if cur:
                    if i['mac'] in vulnerable_devices:
                        vulnerable_devices[i['mac']].append(VulnerabilityType.WeakPassword)
                    else:
                        vulnerable_devices[i['mac']] = VulnerabilityType.WeakPassword
        return vulnerable_devices
