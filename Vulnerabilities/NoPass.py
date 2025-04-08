import ftplib
import ftplib
import telnetlib
#from killerbee import KillerBee
import paho.mqtt.client as mqtt
import subprocess
import logging
import time
from Vulnerabilities.Vulnerability import Vulnerability, VulnerabilityType
from Vulnerabilities.test import check_ftp_anonymous
from vendor_type import DeviceType


class SMTPUserEnumeration(Vulnerability):
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

    📌Перехватывать данные (особенно в Telnet, где трафик не шифруется).

     Использовать сервер для атак (например, рассылки спама или DDoS).''')
        self.methods = '''    Всегда меняйте пароль по умолчанию (если устройство новый, сразу зайдите в настройки).

    Отключите ненужные сервисы (особенно Telnet — он небезопасен в принципе).

🔧 Конкретные действия:

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
            client.disconnect()
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

    def check_telnet_anonymous(ip):
        """
        Проверяет, разрешено ли анонимное подключение к Telnet-серверу.
        :param ip: IP-адрес устройства
        :return: True, если анонимное подключение разрешено, иначе False
        """
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
        check_ftp_anonymous(device['ip'])



    def check(self, devices):
        vulnerable_devices = {}
        print(devices)
        for i in devices:
            if i['type'] != DeviceType.Skip:
                print('device', i['ip'], i['type'])
                cur = self.check_for_device(i)
                if cur:
                    if i['mac'] in vulnerable_devices:
                        vulnerable_devices[i['mac']].append(VulnerabilityType.MQTTPubSub)
                    else:
                        vulnerable_devices[i['mac']] = VulnerabilityType.MQTTPubSub
        return vulnerable_devices
