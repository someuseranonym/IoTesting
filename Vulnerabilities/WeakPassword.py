import asyncio
import socket
import pysnmp
import requests
from pysnmp.entity.engine import SnmpEngine
from pysnmp.hlapi.v3arch import ContextData, UdpTransportTarget, CommunityData
from pysnmp.smi.rfc1902 import ObjectType, ObjectIdentity
from Vulnerability import *
from TypeGetter import *
import paramiko
import argparse
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


async def check_port_async(ip_address, port):
    """
    Асинхронно проверяет, открыт ли порт на заданном IP-адресе.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        await asyncio.get_event_loop().sock_connect(sock, (ip_address, port))
        sock.close()
        return True
    except (socket.timeout, socket.error):
        return False


def brute_force_ssh(device, username_file, password_file):
    if not check_port_async(device['ip'], 22): return False
    try:
        with open(username_file, 'r') as f:
            usernames = [line.strip() for line in f]
        with open(password_file, 'r') as f:
            passwords = [line.strip() for line in f]
    except FileNotFoundError as e:
        print(f"Ошибка: Файл не найден: {e}")
        return

    for username in usernames:
        for password in passwords:
            try:
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


def brute_force_http(device, port, username_file, password_file, success_string):
    """
    Выполняет брутфорс HTTP-аутентификации, перебирая имена пользователей и пароли.
    """
    try:
        with open(username_file, 'r') as f:
            usernames = [line.strip() for line in f]
        with open(password_file, 'r') as f:
            passwords = [line.strip() for line in f]
    except FileNotFoundError as e:
        print(f"Ошибка: Файл не найден: {e}")
        return

    url = f"http://{device['ip']}:{port}"  # ЗАМЕНИТЕ НА РЕАЛЬНЫЙ URL
    for username in usernames:
        for password in passwords:
            data = {'username': username, 'password': password}  # ЗАМЕНИТЕ НА РЕАЛЬНЫЕ ИМЕНА ПОЛЕЙ
            try:
                response = requests.post(url, data=data, timeout=5)  # Добавляем timeout
                if success_string in response.text:  # Ищем строку успеха
                    print(f"[+] Успех! Username: {username}, Пароль: {password}")
                    return
                else:
                    print(f"[-] Неудачная попытка: Username: {username}, Пароль: {password}")
            except requests.exceptions.RequestException as e:  # Обрабатываем исключения
                print(f"[!] Ошибка соединения: {e}")
                return

    print("[-] Пароль не найден в заданных списках.")


def brute_force_snmp(wordlist, snmp_version, ip, port, timeout):
    v_arg = 1 if '2c' == snmp_version else 0

    print(f'Starting SNMPv{snmp_version} bruteforce')

    with open(wordlist, 'r') as in_file:
        communities = in_file.read().splitlines()

    for com in tqdm(communities):

        iterator = pysnmp.hlapi.getCmd(
            SnmpEngine(),
            CommunityData(com, mpModel=v_arg),
            UdpTransportTarget((ip, port), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

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

    def check_for_device(self, device):
        username_file = './WordLists/username.txt'
        passwords_file = './WordLists/passwords.txt'
        match device['type']:
            case DeviceType.Camera:
                brute_force_ssh(device, username_file, passwords_file)
                brute_force_http(device, 80, username_file, passwords_file, "success")
            case DeviceType.Printer:
                brute_force_http(device, 80, username_file, passwords_file, "success")
                brute_force_snmp('./WordLists/snmp_wordlist.txt', '1', device['ip'], 22, 2)
                brute_force_snmp('./WordLists/snmp_wordlist.txt', '2c', device['ip'], 22, 2)
            case 'case3':
                print("Case 3 executed")
            case _:  # Default case (wildcard pattern)
                print("Default case executed")

    def check(self, devices):
        vulnerable_devices = {}
        for i in devices:
            cur = self.check_for_device(i)
            if cur:
                if i['mac'] in vulnerable_devices:
                    vulnerable_devices[i['mac']].append(VulnerabilityType.WeakPassword)
        return vulnerable_devices
