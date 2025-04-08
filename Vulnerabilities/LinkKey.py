from Vulnerabilities.Vulnerability import Vulnerability, VulnerabilityType
from vendor_type import DeviceType


class SMTPUserEnumeration(Vulnerability):
    def __init__(self):
        """
        Инициализация объекта.
        """
        super().__init__()  # Вызов конструктора базового класса
        self.name = "Использование link key Zigbee по умолчанию"
        self.desc = ("Link Key — это пароль для подключения устройств Zigbee (лампы, датчики, розетки)."
                     "Многие устройства используют один и тот же заводской пароль ")
        self.threats = ('''Злоумышленник может перехватить трафик, если знает стандартный ключ.
    Возможность подмены устройств (например, добавление чужого датчика в вашу сеть).
    Перехват и изменение команд (например, взлом умного замка или отключение сигнализации).''')
        self.methods = '''    В Zigbee2MQTT:

        В том же разделе «Параметры Coordinator» введите новый ключ в поле «Network Key».

        Пример случайного ключа (можно сгенерировать тут):
        Copy

        A1:B2:C3:D4:E5:F6:12:34:56:78:90:AB:CD:EF:01:23

        Сохраните настройки и перезапустите Zigbee2MQTT.

    В Home Assistant (ZHA):

        Перейдите в «Настройки» → «Устройства и службы» → «Zigbee».

        Выберите «Настройки сети» → «Сменить ключ сети».

        Введите новый ключ и подтвердите.

    На других платформах (Hubitat, SmartThings):

        Найдите в настройках Zigbee-координатора пункт «Change Network Key» или «Security Key».

        Введите новый ключ и сохраните.

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
