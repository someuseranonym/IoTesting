import socket

from Vulnerabilities.Vulnerability import Vulnerability, VulnerabilityType
from vendor_type import DeviceType


class SMTPUserEnumeration(Vulnerability):
    COMMON_SMTP_PORTS = [25, 465, 587]  # Стандартные порты SMTP
    COMMON_USERS = ['root', 'admin', 'user', 'support']  # Часто используемые имена пользователей

    def __init__(self, timeout: float = 5.0):
        """
        Инициализация объекта.
        """
        super().__init__()  # Вызов конструктора базового класса
        self.ip = ''
        self.type = ''
        self.vulns = {}
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
        self.timeout = timeout

    def check_for_device(self, ip: str, mac: str = None):
        """
        Проверяет устройство на уязвимости SMTP
        :param ip: IP адрес устройства
        :param mac: MAC адрес (опционально, для логирования)
        :return: Словарь с результатами проверок
        """
        results = {
            'smtp_detected': False,
            'vrfy_vulnerable': False,
            'expn_vulnerable': False,
            'rcpt_vulnerable': False
        }

        print(f"\n[🔍] Начинаем проверку SMTP для устройства {ip} ({mac or 'без MAC'})")

        # Проверяем все возможные SMTP порты
        for port in self.COMMON_SMTP_PORTS:
            if self._check_smtp_service(ip, port):
                results['smtp_detected'] = True
                print(f"[ℹ️] Обнаружен SMTP сервер на {ip}:{port}")

                # Проверяем уязвимости
                results['vrfy_vulnerable'] = self._test_vrfy(ip, port)
                results['expn_vulnerable'] = self._test_expn(ip, port)
                results['rcpt_vulnerable'] = self._test_rcpt(ip, port)
                break

        return results['vrfy_vulnerable'] or results['expn_vulnerable'] or results['rcpt_vulnerable']

    def _check_smtp_service(self, ip: str, port: int) -> bool:
        """Проверяет, работает ли SMTP сервер на указанном порту"""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                response = sock.recv(1024).decode().strip()
                return response.startswith("220")
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _test_vrfy(self, ip: str, port: int) -> bool:
        """Проверяет уязвимость VRFY"""
        for user in self.COMMON_USERS:
            try:
                with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                    sock.recv(1024)  # Читаем приветственное сообщение
                    sock.send(f"VRFY {user}\r\n".encode())
                    response = sock.recv(1024).decode().strip()

                    if response.startswith("250") or "User unknown" not in response:
                        print(f"[⚠️] Уязвимость VRFY обнаружена! Ответ сервера: {response}")
                        return True
            except Exception:
                continue
        return False

    def _test_expn(self, ip: str, port: int) -> bool:
        """Проверяет уязвимость EXPN"""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                sock.recv(1024)
                sock.send(b"EXPN test\r\n")
                response = sock.recv(1024).decode().strip()

                if response.startswith("250"):
                    print(f"[⚠️] Уязвимость EXPN обнаружена! Ответ сервера: {response}")
                    return True
        except Exception:
            pass
        return False

    def _test_rcpt(self, ip: str, port: int) -> bool:
        """Проверяет уязвимость RCPT TO"""
        for user in self.COMMON_USERS:
            try:
                with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                    sock.recv(1024)
                    sock.send(b"MAIL FROM: <test@example.com>\r\n")
                    sock.recv(1024)
                    sock.send(f"RCPT TO: <{user}>\r\n".encode())
                    response = sock.recv(1024).decode().strip()

                    if response.startswith("250"):
                        print(f"[⚠️] Уязвимость RCPT TO обнаружена для пользователя {user}! Ответ: {response}")
                        return True
            except Exception:
                continue
        return False

    def append(self, device):
        if device['mac'] in self.vulns:
            self.vulns[device['mac']].append(SMTPUserEnumeration())
        else:
            self.vulns[device['mac']] = [SMTPUserEnumeration()]
        print(self.vulns)
        self.vulns[device['mac']][-1].ip = device['ip']
        self.vulns[device['mac']][-1].type = device['тип']

    def check(self, devices):
        vulnerable_devices = {}
        print(devices)
        for i in devices:
            if i['type'] in [DeviceType.Camera, DeviceType.Printer]:
                print('device', i['ip'], i['type'])
                cur = self.check_for_device(i['ip'], i['mac'])
                if cur:
                    self.append(i)
        return self.vulns