import ftplib
import ftplib
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

    def check_mqtt_anonymous(self, ip):
        client = mqtt.Client()
        try:
            client.connect(ip, 1883, 60)  # Подключение к MQTT-брокеру
            return client.is_connected()
        finally:
            client.disconnect()
    def check_ftp_anonymous(self, ip):
        try:
            with ftplib.FTP(ip) as ftp:  # Используем контекстный менеджер для автоматического закрытия соединения
                ftp.login()  # Попытка анонимного входа
                return True
        except ftplib.error_perm:
            return False

    def check_telnet_anonymous(self, ip):
        try:
            with telnetlib.Telnet(
                    ip) as telnet:  # Используем контекстный менеджер для автоматического закрытия соединения
                telnet.read_until(b"login: ")  # Ожидаем запроса на логин
                telnet.write(b"\n")  # Пытаемся подключиться без пароля
                return True
        except Exception as e:
            logging.error(f"Ошибка при проверке Telnet на анонимное подключение: {e}")
            return False
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
                    if i['mac'] in vulnerable_devices:
                        vulnerable_devices[i['mac']].append(VulnerabilityType.NoPass)
                    else:
                        vulnerable_devices[i['mac']] = VulnerabilityType.NoPass
                    vulnerable_devices[i['mac']][-1].name += ' по протоколу MQTT'
            if i['type'] in [DeviceType.Camera, DeviceType.Printer]:
                print('device', i['ip'], i['type'])
                cur = self.check_ftp_anonymous(i['ip'])
                if cur:
                    if i['mac'] in vulnerable_devices:
                        vulnerable_devices[i['mac']].append(VulnerabilityType.NoPass)
                    else:
                        vulnerable_devices[i['mac']] = VulnerabilityType.NoPass
                    vulnerable_devices[i['mac']][-1].name += ' по протоколу FTP'
            if i['type'] in [DeviceType.Camera, DeviceType.Printer]:
                print('device', i['ip'], i['type'])
                cur = self.check_telnet_anonymous(i['ip'])
                if cur:
                    if i['mac'] in vulnerable_devices:
                        vulnerable_devices[i['mac']].append(VulnerabilityType.NoPass)
                    else:
                        vulnerable_devices[i['mac']] = VulnerabilityType.NoPass
                    vulnerable_devices[i['mac']][-1].name += ' по протоколу Telnet'
        return vulnerable_devices
