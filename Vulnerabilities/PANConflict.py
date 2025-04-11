import time
from Vulnerabilities.Vulnerability import Vulnerability, VulnerabilityType
from killerbee import KillerBee
from vendor_type import DeviceType


class PANConflict(Vulnerability):
    def __init__(self):
        """
        Инициализация объекта.
        """
        super().__init__()  # Вызов конструктора базового класса
        self.ip = ''
        self.type = ''
        self.vulns={}
        self.name = "Конфликт PAN-идентификаторов Zigbee"
        self.desc = '''PAN-ID (Personal Area Network Identifier) — это уникальный номер Zigbee-сети. Если рядом есть две сети с одинаковым PAN-ID, устройства могут:

    Подключаться к чужой сети

    Терять связь с роутером

    Создавать помехи в работе'''
        self.threats = ('''Посторонние устройства могут несанкционированно подключаться к вашей сети

    Ваши устройства могут случайно перейти в соседнюю сеть

    Снижается надёжность и скорость работы''')
        self.methods = '''     Выберите новый PAN-ID:

        Диапазон: От 0x0001 до 0xFFF7 (1–65527 в десятичной системе)

        Как выбрать: Лучше случайное число (например, 0x3D8A)

    Примените изменения:

        Zigbee2MQTT:
        yaml
        advanced:
          pan_id: 0x3D8A  # Ваш новый PAN-ID

        → Сохраните и перезапустите сервис.

        Home Assistant (ZHA):
        Через интерфейс → Change Network Settings → Укажите новый PAN-ID.

    Переподключите устройства (если не переподключились автоматически).

'''

    def check_for_device(self, device, packets=None):
        pan_ids = set()
        conflicts = set()

        for packet in packets:
            if packet['type'] == 'ZIGBEE':
                pan_id = packet['pan_id']
                source_mac = packet['src_mac']

                # Проверяем, соответствует ли MAC или IP устройству
                if (device['mac'] and source_mac.lower() == device['mac'].lower()) or \
                   (device['ip'] and packet['src_ip'] == device['ip']):
                    if pan_id in pan_ids:
                        conflicts.add(pan_id)
                    else:
                        pan_ids.add(pan_id)

        return conflicts
    def append(self, device):
        if device['mac'] in self.vulns:
            self.vulns[device['mac']].append(PANConflict())
        else:
            self.vulns[device['mac']] = [PANConflict()]
        print(self.vulns)
        self.vulns[device['mac']][-1].ip=device['ip']
        self.vulns[device['mac']][-1].type = device['тип']
    def check(self, devices, packets):
        vulnerable_devices = {}
        kb = KillerBee()
        print(devices)
        for i in devices:
            if i['type'] in [DeviceType.Lamp, DeviceType.Socket, DeviceType.Thermostat, DeviceType.Lock]:
                print('device', i['ip'], i['type'])
                cur = self.check_for_device(i, kb)
                if cur:
                    self.append(i)
        return self.vulns
