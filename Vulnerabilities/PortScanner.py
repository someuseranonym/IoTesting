import masscan
from Vulnerabilities.Vulnerability import *
class PortScanner(Vulnerability):
    def __init__(self):
        """
        Инициализация объекта.
        """
        super().__init__()  # Вызов конструктора базового класса
        self.name = "Открытые порты"
        self.port_problems = {
            "554": {
                "name": "RTSP Unauthorized Access",
                "description": "Открытый RTSP-поток без аутентификации",
                "attack": "Перехват видеопотока через rtsp://{ip}:554/",
                "fix": "Закрыть порт или включить аутентификацию"
            },
            "80": {
                "name": "Web Interface Vulnerabilities",
                "description": "Уязвимости веб-интерфейса (XSS, CSRF, RCE)",
                "attack": "Атаки через веб-интерфейс камеры",
                "fix": "Обновить прошивку, сменить пароль по умолчанию"
            },
            "9000": {
                "name": "ONVIF Weak Authentication",
                "description": "Слабая аутентификация ONVIF",
                "attack": "Перебор паролей ONVIF-сервиса",
                "fix": "Отключить ONVIF или использовать сложные пароли"
            }
        }
                # переписать
        self.desc = "Обнаружен открытые порты"
        self.threats = ("Злоумышленник получит полный контроль над устройством. "
                        "Это означает, что он может изменять настройки, управлять функциями устройства;"
                        "получить доступ к конфиденциальной информации, собираемой устройством. "
                        "Например, он может просматривать видео с камер видеонаблюдения, получать данные с датчиков;"
                        "Использовать устройство для распространения вредоносного ПО на другие устройства в локальной сети.")
        self.methods = ("Установите пароль длины минимум 10 символов. Он должен содержать заглавные"
                        " и строчные буквы, цифры и спец символы. "
                        "Не используйте простые последовательности («12345», «qwerty»)")
        self.masscan = masscan.PortScanner()

    def check(self, devices):
        open_ports = {}

        for device in devices:
            if device['type'] != DeviceType.Skip:
                target_ip = device['ip']
                cur = []
                print(f"Scanning {target_ip}...")

                # Set up scanning parameters
                try:
                    self.masscan.scan(target_ip, ports='22,80,8080', arguments='--max-rate 1000')
                except Exception as e:
                    print(f"Error scanning {target_ip}: {e}")
                    continue  # Skip this device if there's an error

                # Check if there are results for the target IP
                if target_ip in self.masscan.all_hosts:
                    for proto in self.masscan[target_ip]:
                        ports = self.masscan[target_ip][proto].keys()
                        for port in ports:
                            if self.masscan[target_ip][proto][port]['state'] == 'open':
                                cur.append(str(port))
                                print(f"⚡ Обнаружен открытый порт: {port}/{proto} на {target_ip}")
                else:
                    print(f"No open ports found on {target_ip}")

                open_ports[target_ip] = cur

        return open_ports