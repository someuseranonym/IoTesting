from Vulnerabilities.Vulnerability import Vulnerability, VulnerabilityType
from killerbee import KillerBee
from vendor_type import DeviceType


class OpenKeyTransfer(Vulnerability):
    def __init__(self):
        """
        Инициализация объекта.
        """
        super().__init__()  # Вызов конструктора базового класса
        self.ip = ''
        self.type = ''
        self.vulns={}
        self.name = "Небезопасная передача ключа Zigbee"
        self.desc = ("При подключении Zigbee-устройств (лампы, датчики) ключ шифрования иногда передаётся в открытом виде")
        self.threats = ('''Злоумышленник может перехватить ключ и подключиться к вашей сети.

    Возможен взлом устройств (например, отключение сигнализации или контроль умного дома).''')
        self.methods = '''    Обновите прошивку:

        Контроллера

        Zigbee-устройств

    Отключите ненужные функции:

        Touchlink

        "Быстрое подключение"

    Настройте брандмауэр:

        Ограничьте доступ к порту Zigbee (обычно 8080 для Zigbee2MQTT)

'''
    def append(self, device):
        if device['mac'] in self.vulns:
            self.vulns[device['mac']].append(OpenKeyTransfer())
        else:
            self.vulns[device['mac']] = [OpenKeyTransfer()]
        print(self.vulns)
        self.vulns[device['mac']][-1].ip=device['ip']
        self.vulns[device['mac']][-1].type = device['тип']
    def check_for_device(self, device, packets):
        for packet in packets:
            if packet['type'] == 'ZIGBEE' and 'key' in packet:  # Предполагаем, что ключ передается в поле 'key'
                source_mac = packet['src_mac']
                # Проверяем, соответствует ли MAC или IP устройству
                if (device['mac'] and source_mac.lower() == device['mac'].lower()) or \
                   (device['ip'] and packet['src_ip'] == device['ip']):
                    key_value = packet['key']
                    print(f"Открытая передача ключа обнаружена от устройства {source_mac}: {key_value}")
                    return True

        print("Открытая передача ключей не обнаружена.")
        return False

    def check(self, devices):
        vulnerable_devices = {}
        print(devices)
        for i in devices:
            if i['type'] in [DeviceType.Lamp, DeviceType.Socket, DeviceType.Thermostat, DeviceType.Lock]:
                print('device', i['ip'], i['type'])
                cur = self.check_for_device(i)
                if cur:
                    self.append(i)
        return self.vulns
