import time

from paho import mqtt

from Vulnerabilities.Vulnerability import Vulnerability, VulnerabilityType
from vendor_type import DeviceType


class MQTTPubSub(Vulnerability):
    def __init__(self):
        """
        Инициализация объекта.
        """
        super().__init__()  # Вызов конструктора базового класса
        self.name = "Возможность публикации сообщения и подписки на топик по протоколу MQTT"
        self.desc = ("Злоумышленник может получить доступ к сообщениям, которые отправляются между устройствами, "
                     "или даже отправлять свои собственные сообщения.")
        self.threats = ("Злоумышленник может подписаться на топики управления умными устройствами и отправлять команды,"
                        " которые могут привести к неправильной работе устройства"
                        "(например, включение/выключение света или термостата)."
                        "Злоумышленник может перехватывать сообщения между устройствами и изменять их содержимое."
                        "Это может привести к тому, что устройства будут выполнять нежелательные действия"
                        "или передавать ложную информацию.")
        self.methods = '''Шаг 0: Обновите программное обеспечение
        Проверьте наличие обновлений:
            Убедитесь, что все ваши устройства и MQTT-брокер (например, Mosquitto, HiveMQ) обновлены до последней версии.
            Установите все доступные обновления безопасности. Для этого Посетите веб-сайт производителя вашего умного устройства 
            (например, камеры, термостаты, датчики и т.д.). Обычно на сайте есть раздел "Поддержка" или "Загрузки", где можно найти обновления прошивки.
            Если ваше устройство управляется через мобильное приложение, проверьте наличие обновлений в самом приложении. Обычно в настройках приложения
             есть раздел "Обновления" или "Проверить обновления".Проверьте настройки ваших устройств и программного обеспечения на наличие опции автоматического обновления. Э
             то поможет вам всегда иметь актуальную версию без необходимости вручную проверять обновления.
             Шаг 1: Определите MQTT-брокер

Убедитесь, что у вас установлен MQTT-брокер (например, Mosquitto). Если не уверены, проверьте документацию устройства или обратитесь к производителю.
Шаг 2: Установка Mosquitto
Для Windows:

    Скачайте установочный файл с официального сайта Mosquitto.
    Запустите установщик и следуйте инструкциям.

Для Ubuntu/Debian:

    Откройте терминал.
    Выполните команды:
    bash

    sudo apt updatesudo apt install mosquitto mosquitto-clients

Шаг 3: Настройка аутентификации
1. Создайте файл паролей

    Откройте терминал.
    Выполните команду:
    bash

    mosquitto_passwd -c /etc/mosquitto/passwd username

    Замените username на желаемое имя пользователя и введите пароль.

2. Настройте конфигурацию Mosquitto

    Откройте файл конфигурации (обычно /etc/mosquitto/mosquitto.conf на Linux или в папке установки на Windows).
    Добавьте следующие строки:
    Код

    password_file /etc/mosquitto/passwdallow_anonymous false

    Сохраните изменения.

3. Перезапустите Mosquitto

    Для Linux:
    bash

    sudo systemctl restart mosquitto

    Для Windows: Перезапустите службу "Mosquitto Broker" через "Службы" (Services).

Шаг 4: Проверка настройки

    Публикация сообщения:
    bash

mosquitto_pub -h localhost -t test/topic -m "Hello World" -u username -P password

Подписка на тему:
bash

    mosquitto_sub -h localhost -t test/topic -u username -P password

Если все настроено правильно, вы увидите сообщение "Hello World".
'''


    def check_for_device(self, device):
        ip = device['ip']
        received_message = False

        def on_message(client, userdata, message):
            """Обработчик сообщений MQTT."""
            nonlocal received_message
            if message.payload.decode() == "Test Message":
                received_message = True

        client = mqtt.Client()
        try:
            client.connect(ip, 1883, 60)  # Подключение к MQTT-брокеру
            client.loop_start()  # Запуск цикла обработки сообщений
            client.subscribe("test/topic")  # Подписка на топик
            client.publish("test/topic", "Test Message")  # Публикация сообщения
            client.on_message = on_message  # Установка обработчика сообщений
            time.sleep(2)  # Ожидание доставки сообщения
            client.loop_stop()  # Остановка цикла обработки сообщений
            return received_message
        finally:
            client.disconnect()
    def check(self, devices):
        vulnerable_devices = {}
        print(devices)
        for i in devices:
            if i['type'] in [DeviceType.Sensor, DeviceType.Counter, DeviceType.Socket, DeviceType.light_switch]:
                print('device', i['ip'], i['type'])
                cur = self.check_for_device(i)
                if cur:
                    if i['mac'] in vulnerable_devices:
                        vulnerable_devices[i['mac']].append(VulnerabilityType.MQTTPubSub)
                    else:
                        vulnerable_devices[i['mac']] = VulnerabilityType.MQTTPubSub
        return vulnerable_devices
