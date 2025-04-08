from Vulnerabilities.Vulnerability import Vulnerability, VulnerabilityType
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

    def check_for_device(self, device):
        pass

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
