from Vulnerabilities.Vulnerability import Vulnerability, VulnerabilityType
from killerbee import KillerBee
from vendor_type import DeviceType
LINK_KEY = bytes.fromhex("5A 69 67 42 65 65 41 6C 6C 69 61 6E 63 65 30 39")

class LinkKey(Vulnerability):
    def __init__(self):
        """
        Инициализация объекта.
        """
        super().__init__()  # Вызов конструктора базового класса
        self.ip = ''
        self.type = ''
        self.vulns ={}
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

    def append(self, device):
        if device['mac'] in self.vulns:
            self.vulns[device['mac']].append(LinkKey())
        else:
            self.vulns[device['mac']] = [LinkKey()]
        print(self.vulns)
        self.vulns[device['mac']][-1].ip=device['ip']
        self.vulns[device['mac']][-1].type = device['тип']

    def check_for_device(self, device, packets):
        for packet in packets:
            if packet['type'] == 'ZIGBEE_APS':
                source_mac = packet['src_mac']

                # Проверяем, соответствует ли MAC или IP устройству
                if (device['mac'] and source_mac.lower() == device['mac'].lower()) or \
                   (device['ip'] and packet['src_ip'] == device['ip']):
                    aps_payload = packet['payload']
                    if LINK_KEY in aps_payload:
                        print(f"Link Key найден в пакете APS от устройства {source_mac}.")
                        return True

        print("Link Key не найден.")
        return False

    def check(self, devices, packets):
        print(devices)
        for i in devices:
            if i['type'] in [DeviceType.Lamp, DeviceType.Socket, DeviceType.Thermostat, DeviceType.Lock]:
                print('device', i['ip'], i['type'])
                cur = self.check_for_device(i)
                if cur:
                    self.append(i)
        return self.vulns
