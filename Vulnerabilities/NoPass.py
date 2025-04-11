import ftplib
import ftplib
import socket
import telnetlib
#from killerbee import KillerBee
import paho.mqtt.client as mqtt
import subprocess
import logging
import time
from Vulnerabilities.Vulnerability import Vulnerability, VulnerabilityType

from vendor_type import DeviceType


class NoPass(Vulnerability):
    def __init__(self):
        """
        Инициализация объекта.
        """
        super().__init__()  # Вызов конструктора базового класса
        self.name = "Возможность входа без пароля"
        self.timeout = 1.0
        self.ip = ''
        self.type = ''
        self.vulns={}
        self.desc = ("Некоторые сервисы (MQTT, FTP, Telnet) могут быть настроены так, что позволяют подключаться без пароля или с стандартными/слабыми учетными данными.")
        self.threats = ('''то позволяет злоумышленникам:

     Подключаться без авторизации и получать доступ к данным.

     Читать, изменять или удалять файлы (в случае FTP).

    Перехватывать данные (особенно в Telnet, где трафик не шифруется).

     Использовать сервер для атак (например, рассылки спама или DDoS).''')
        self.methods = '''    Всегда меняйте пароль по умолчанию (если устройство новый, сразу зайдите в настройки).

    Отключите ненужные сервисы (особенно Telnet — он небезопасен в принципе).

Конкретные действия:

MQTT:

    Найдите в настройках устройства пункт «MQTT» → «Аутентификация».

    Включите:

        Запретить анонимный доступ

        Требовать пароль

    Задайте сложный пароль (лучше использовать менеджер паролей).
FTP:

    В настройках FTP-сервера найдите:

        Anonymous access → Выключить

        Password required → Включить
Telnet:

    Полностью отключите Telnet — замените его на SSH (если устройство поддерживает).

    Для старых устройств:

        Найдите в настройках «Удалённый доступ» → «Отключить Telnet».

'''

    def check_mqtt_anonymous(self, ip: str) -> bool:
        """Проверяет доступность анонимного MQTT"""
        client = mqtt.Client()
        client.connect_timeout = self.timeout
        try:
            client.connect(ip, 1883, keepalive=60)
            client.loop_start()
            time.sleep(0.5)  # Даем время на установку соединения
            connected = client.is_connected()
            client.disconnect()
            return connected
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logging.debug(f"MQTT connection to {ip} failed: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"MQTT error with {ip}: {str(e)}")
            return False
    def check_ftp_anonymous(self, ip: str) -> bool:
        """Проверяет доступность анонимного FTP"""
        try:
            with ftplib.FTP(timeout=self.timeout) as ftp:
                ftp.connect(ip, timeout=self.timeout)
                try:
                    ftp.login()  # Анонимный вход
                    return True
                except ftplib.error_perm:
                    return False
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logging.debug(f"FTP connection to {ip} failed: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"FTP error with {ip}: {str(e)}")
            return False

    def check_telnet_anonymous(self, ip: str) -> bool:
        """Проверяет доступность анонимного Telnet"""
        try:
            with telnetlib.Telnet(ip, timeout=self.timeout) as telnet:
                telnet.read_until(b"login: ", timeout=self.timeout)
                telnet.write(b"\n")
                response = telnet.read_until(b"Password:", timeout=self.timeout)
                return b"Login incorrect" not in response
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logging.debug(f"Telnet connection to {ip} failed: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"Telnet error with {ip}: {str(e)}")
            return False
    def append(self, device, text):
        if device['mac'] in self.vulns:
            self.vulns[device['mac']].append(NoPass())
        else:
            self.vulns[device['mac']] = [NoPass()]
        print(self.vulns)
        self.vulns[device['mac']][-1].name += ' '+text
        self.vulns[device['mac']][-1].ip=device['ip']
        self.vulns[device['mac']][-1].type = device['тип']
    def check_for_device(self, device):
        pass



    def check(self, devices):
        vulnerable_devices = {}
        print(devices)
        for i in devices:
            if i['type'] in [DeviceType.Sensor, DeviceType.Counter, DeviceType.Socket, DeviceType.light_switch]:
                print('device', i['ip'], i['type'])
                cur = self.check_mqtt_anonymous(i['ip'])
                if cur:
                    self.append(i, ' по протоколу MQTT')
            if i['type'] in [DeviceType.Camera, DeviceType.Printer]:
                print('device', i['ip'], i['type'])
                cur = self.check_ftp_anonymous(i['ip'])
                if cur:
                    self.append(i, ' по протоколу FTP')
            if i['type'] in [DeviceType.Camera, DeviceType.Printer]:
                print('device', i['ip'], i['type'])
                cur = self.check_telnet_anonymous(i['ip'])
                if cur:
                    self.append(i, ' по протоколу Telnet')
        return self.vulns
