import masscan
from Vulnerabilities.Vulnerability import *
from vendor_type import DeviceType


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
        self.desc = '''омпьютеры и серверы используют порты для обмена данными в сети. Например:

    Порт 80 — HTTP (веб-сайты)

    Порт 22 — SSH (удалённое управление)

    Порт 3389 — RDP (подключение к рабочему столу)

Открытый порт — это дверь, через которую можно подключиться к устройству. Если порт открыт и неправильно настроен, злоумышленники могут этим воспользоваться.'''
        self.threats = '''    Несанкционированный доступ

        Злоумышленники могут найти уязвимые порты через сканеры (например, Shodan) и проникнуть в систему.

    Атаки на уязвимые сервисы

        Если на порту работает старая или небезопасная программа (например, устаревший FTP или RDP), её могут взломать.

    DoS-атаки

        Открытые порты могут использоваться для перегрузки системы запросами, что приведёт к её отказу.

    Заражение вирусами

        Через открытые порты могут проникнуть трояны, черви и другие вредоносные программы.'''
        self.methods = '''    Остановите службу, которая использует порт:

        Windows: Диспетчер задач → вкладка "Службы".

        Linux/macOS:
        bash
        Copy

        sudo systemctl stop имя_службы
        sudo systemctl disable имя_службы

    Настройте брандмауэр:

        Windows:

            Откройте Брандмауэр Защитника Windows → "Дополнительные параметры".

            В "Правила для входящих подключений" найдите порт → отключите/удалите.

        Linux (ufw):
        bash
        Copy

        sudo ufw deny номер_порта  # например, sudo ufw deny 22

        macOS:
        bash
        Copy

        sudo pfctl -f /etc/pf.conf  # настройте файл правил

        Роутер: Закройте порты в настройках NAT/Port Forwarding.

    Измените конфигурацию сервиса (если порт нужен, но должен быть защищен):

        Например, для SSH (порт 22) отредактируйте /etc/ssh/sshd_config (Linux) или настройки OpenSSH (Windows).'''
        self.masscan = masscan.PortScanner()

    def check(self, devices):
        open_ports = {}
        vulns = {}
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
                                if device['mac'] in vulns:
                                    vulns[device['mac']].append(VulnerabilityType.OpenPort)
                                else:
                                    vulns[device['mac']] = VulnerabilityType.OpenPort
                else:
                    print(f"No open ports found on {target_ip}")

                open_ports[target_ip] = cur
        return vulns