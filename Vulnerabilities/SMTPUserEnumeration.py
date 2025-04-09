import socket

from Vulnerabilities.Vulnerability import Vulnerability, VulnerabilityType
from vendor_type import DeviceType


class SMTPUserEnumeration(Vulnerability):
    def __init__(self):
        """
        Инициализация объекта.
        """
        super().__init__()  # Вызов конструктора базового класса
        self.name = "Перечисление пользователей SMTP-сервером"
        self.desc = ("Злоумышленник может получить список всех пользователей, зарегистрированных на SMTP-сервере "
                     "(сервере, который отправляет и получает электронные письма).")
        self.threats = ("Злоумышленник может использовать полученные адреса электронной почты для попытки подбора паролей, "
                        "что может привести к несанкционированному доступу к учетным записям пользователей."
                        "Получив список пользователей, злоумышленник может отправить целевые фишинговые письма, чтобы украсть учетные данные."
                        "Зная имена пользователей, злоумышленник может легче манипулировать жертвами через социальную инженерию.")
        self.methods = '''1. Проверьте настройки вашего почтового клиента

    Как сделать:
        Откройте ваш почтовый клиент (например, Outlook, Thunderbird).
        Перейдите в настройки учетной записи (обычно это можно сделать через меню "Файл" или "Настройки").
        Найдите раздел, связанный с настройками сервера исходящей почты (SMTP).
        Убедитесь, что включено шифрование (SSL/TLS). Обычно это можно выбрать в выпадающем меню рядом с полем для ввода порта. Для SMTP обычно используется порт 465 (SSL) или 587 (TLS).

2. Измените настройки безопасности

    Как сделать:
        Если вы администратор почтового сервера, вам нужно будет получить доступ к его настройкам. Это может быть сделано через панель управления хостинга или через интерфейс управления сервером.
        Найдите раздел настроек SMTP и отключите команды VRFY и EXPN. Это может быть сделано через конфигурационные файлы или графический интерфейс, в зависимости от используемого программного обеспечения (например, Postfix, Exim).

3. Используйте сложные пароли

    Как сделать:
        Перейдите в настройки безопасности вашего почтового аккаунта.
        Измените пароль на более сложный: используйте комбинацию букв (верхнего и нижнего регистра), цифр и специальных символов. Например: P@ssw0rd!2023.
        Убедитесь, что этот пароль уникален и не используется на других сайтах.

4. Включите двухфакторную аутентификацию (2FA)

    Как сделать:
        Зайдите в настройки безопасности вашего почтового аккаунта.
        Найдите опцию "Двухфакторная аутентификация" или "Подтверждение в два шага".
        Следуйте инструкциям для включения этой функции. Обычно вам потребуется указать номер телефона или установить приложение для аутентификации (например, Google Authenticator).

5. Регулярно проверяйте свои учетные записи

    Как сделать:
        Периодически входите в свой почтовый аккаунт и проверяйте папку "Входящие" на наличие подозрительных писем.
        Проверьте историю входов в аккаунт (если такая функция доступна) на наличие незнакомых устройств или местоположений.

'''


    def check_for_device(self, device) -> bool:
        """Проверка перечисления пользователей SMTP сервером"""
        ip = device['ip']
        print(f"Проверка SMTP сервера устройства {ip} на перечисление пользователей...")

        # Получаем параметры SMTP сервера из конфигурации устройства
        device_config = self.fake_devices.get(ip, {})
        if not device_config.get("smtp_user_enum", False):
            print(f"[+] SMTP сервер устройства {ip} не позволяет перечислять пользователей")
            return False

        smtp_host = device_config.get("smtp_host", "localhost")
        smtp_port = device_config.get("smtp_port", 25)

        try:
            # Создаем соединение с SMTP сервером
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((smtp_host, smtp_port))
            response = sock.recv(1024).decode().strip()

            if not response.startswith("220"):
                print(f"[+] SMTP сервер {ip} не отвечает должным образом")
                return False

            # Тестируем команду VRFY
            sock.send(b"VRFY root\r\n")
            response = sock.recv(1024).decode().strip()
            if response.startswith("250"):
                print(f"[!] Уязвимость: SMTP сервер {ip} позволяет перечислять пользователей через VRFY")
                return True

            # Тестируем команду EXPN
            sock.send(b"EXPN test\r\n")
            response = sock.recv(1024).decode().strip()
            if response.startswith("250"):
                print(f"[!] Уязвимость: SMTP сервер {ip} позволяет перечислять пользователей через EXPN")
                return True

            # Тестируем команду RCPT (нужно начать с MAIL FROM)
            sock.send(b"MAIL FROM: <test@example.com>\r\n")
            sock.recv(1024)  # Пропускаем ответ

            sock.send(b"RCPT TO: <root>\r\n")
            response = sock.recv(1024).decode().strip()
            if response.startswith("250"):
                print(f"[!] Уязвимость: SMTP сервер {ip} позволяет перечислять пользователей через RCPT TO")
                return True

            print(f"[+] SMTP сервер устройства {ip} не позволяет перечислять пользователей")
            return False

        except Exception as e:
            print(f"[!] Ошибка при проверке SMTP сервера: {str(e)}")
            return False
        finally:
            try:
                sock.close()
            except:
                pass

    def check(self, devices):
        vulnerable_devices = {}
        print(devices)
        for i in devices:
            if i['type'] in [DeviceType.Camera, DeviceType.Printer]:
                print('device', i['ip'], i['type'])
                cur = self.check_for_device(i)
                if cur:
                    if i['mac'] in vulnerable_devices:
                        vulnerable_devices[i['mac']].append(VulnerabilityType.SMTPUserEnumration)
                    else:
                        vulnerable_devices[i['mac']] = VulnerabilityType.SMTPUserEnumration
        return vulnerable_devices
