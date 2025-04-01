import asyncio
import ftplib
import socket
import telnetlib
from pysnmp.hlapi import *
import pysnmp
import requests
from pysnmp.entity.engine import SnmpEngine
from pysnmp.hlapi.v3arch import ContextData, UdpTransportTarget, CommunityData
from pysnmp.smi.rfc1902 import ObjectType, ObjectIdentity
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


def brute_force_http(device, port, usernames, passwords, success_string):
    """
    Выполняет брутфорс HTTP-аутентификации, перебирая имена пользователей и пароли.
    """
    print('http bruteforce')
    url = f"http://{device['ip']}:{port}"
    i = 1

    for username in usernames:
        for password in passwords:
            data = {'username': username, 'password': password}
            try:
                time.sleep(0.7)
                response = requests.post(url, data=data, timeout=5)  # Добавляем timeout
                if response.status_code == 200:
                    print(f"Success! Username: {username}, password: {password}")

                    # Дальнейшая проверка (очень важна!)
                    if 'Logout' in response.text:
                        print("Успешная аутентификация (по наличию Logout)")

                    else:
                        print("Код 200, но признаков успешной аутентификации нет. Требуется дальнейший анализ!")
                        #return False  # Или продолжить перебор
                else:
                    print(f"Failed. Status code: {response.status_code if response else 'No response'}")

                #print(f"[-] Неудачная попытка: Username: {username}, Пароль: {password}")
            except requests.exceptions.RequestException as e:  # Обрабатываем исключения
                print(f"[!] Ошибка соединения: {e}")
                return
            i+=1

    print("[-] Пароль не найден в заданных списках.")


def brute_force_snmp(wordlist, snmp_version, ip, port, timeout):
    v_arg = 1 if '2c' == snmp_version else 0

    print(f'Starting SNMPv{snmp_version} bruteforce')

    with open(wordlist, 'r') as in_file:
        communities = in_file.read().splitlines()

    for com in tqdm(communities):
        time.sleep(0.2)

        # Используем getCmdGen вместо getCmd
        g = getCmdGen()

        # Передаем аргументы в g.getCmd
        errorIndication, errorStatus, errorIndex, varBinds = next(
            g.getCmd(
                SnmpEngine(),
                CommunityData(com, mpModel=v_arg),
                UdpTransportTarget((ip, port), timeout=timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            )
        )

        if errorIndication:
            pass
            # print(errorIndication)

        elif errorStatus:
            pass
            # print('%s at %s' % (errorStatus.prettyPrint(),errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            tqdm.write(f"Found community name {com} !")
            for varBind in varBinds:
                tqdm.write(' = '.join([x.prettyPrint() for x in varBind]))


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
        self.methods = ("Установите пароль длины минимум 10 символов. Он должен содержать заглавные"
                        " и строчные буквы, цифры и спец символы. "
                        "Не используйте простые последовательности («12345», «qwerty»)")

    def check_for_device(self, device, usernames, passwords):
        print('check', device['mac'], device['type'])

        if device['type'] in [DeviceType.light_switch, DeviceType.Lamp, DeviceType.Counter, DeviceType.Socket]:
            brute_force_http(device, 80, usernames, passwords, "200")
            brute_force_mqtt(device, 1883, usernames, passwords)
            check_ftp_credentials(device['ip'], 21, usernames, passwords)
            check_telnet_credentials(device['ip'], 23, usernames, passwords)
        match device['type']:
            case DeviceType.Camera:
                brute_force_ssh(device, usernames, passwords)
                brute_force_http(device, 80, usernames, passwords, "success")
                #brute_force_snmp('Vulnerabilities/WordLists/snmp_wordlist.txt', '1', device['ip'], 22, 2)
                #brute_force_snmp('Vulnerabilities/WordLists/snmp_wordlist.txt', '2c', device['ip'], 22, 2)
            case DeviceType.Printer:
                brute_force_http(device, 80, usernames, passwords, "200")
                brute_force_snmp('Vulnerabilities/WordLists/snmp_wordlist.txt', '1', device['ip'], 22, 2)
                brute_force_snmp('Vulnerabilities/WordLists/snmp_wordlist.txt', '2c', device['ip'], 22, 2)
            case DeviceType.Thermostat:
                brute_force_ssh(device, usernames, passwords)
                brute_force_http(device, 80, usernames, passwords, "200")
                brute_force_mqtt(device, 1883, usernames, passwords)
            case DeviceType.Sensor:
                brute_force_http(device, 80, usernames, passwords, "200")
                brute_force_mqtt(device, 1883, usernames, passwords)
                brute_force_snmp('./WordLists/snmp_wordlist.txt', '1', device['ip'], 22, 2)
                brute_force_snmp('./WordLists/snmp_wordlist.txt', '2c', device['ip'], 22, 2)
            case _:  # Default case (wildcard pattern)
                pass

    def check(self, devices):
        username_file = 'Vulnerabilities/WordLists/username.txt'
        passwords_file = ['Vulnerabilities/WordLists/rockyou2.txt']
        usernames = []
        passwords = []
        try:
            with open(username_file, 'r') as f:
                usernames1 = [line.strip() for line in f]
                for i in usernames1:
                    usernames.append(i)
            for i in passwords_file:
                with open(i, 'r', encoding='utf-8') as f:
                    passwords1 = [line.strip() for line in f]
                    for i in passwords1:
                        passwords.append(i)
        except FileNotFoundError as e:
            print(f"Ошибка: Файл не найден: {e}")
            return
        vulnerable_devices = {}
        for i in devices:
            cur = self.check_for_device(i, usernames, passwords)
            if cur:
                if i['mac'] in vulnerable_devices:
                    vulnerable_devices[i['mac']].append(VulnerabilityType.WeakPassword)
        return vulnerable_devices
