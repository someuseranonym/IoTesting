from Vulnerabilities.Vulnerability import Vulnerability, VulnerabilityType
from vendor_type import DeviceType


class SMTPUserEnumeration(Vulnerability):
    def __init__(self):
        """
        Инициализация объекта.
        """
        super().__init__()  # Вызов конструктора базового класса
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

    def check_zigbee_insecure_keys(pcap_file):
        """
        Проверяет, передаются ли ключи ZigBee в незашифрованном виде.
        :param pcap_file: Путь к файлу с захваченным трафиком ZigBee
        :return: True, если ключи передаются в открытом виде, иначе False
        """
        kb = KillerBee()
        kb.load_file(pcap_file)  # Загрузка файла с трафиком
        for packet in kb.packets:
            if packet.is_aps() and packet.aps_command == 0x05:  # Проверка APS-команды Transport Key
                if packet.payload and b'\x00' in packet.payload:  # Проверка на открытый ключ
                    return True
        return False
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
