# no_auth_servers_ftp.py
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import warnings
import logging

def run_ftp_server():
    # Настройка логирования
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('pyftpdlib')
    
    # Отключаем предупреждения
    warnings.filterwarnings("ignore", category=RuntimeWarning)
    
    # Создаем авторизатор с анонимным доступом
    authorizer = DummyAuthorizer()
    
    # Добавляем анонимный доступ с полными правами
    # Первый параметр - корневая директория (текущая ".")
    # Второй параметр - права: 
    #   e - изменение директории
    #   l - список файлов
    #   r - чтение
    #   a - дозапись
    #   d - удаление
    #   f - запись
    #   m - создание директорий
    #   w - переименование
    authorizer.add_anonymous(".", perm="elradfmw")
    
    # Настраиваем обработчик
    handler = FTPHandler
    handler.authorizer = authorizer
    
    # Настройка IP и порта (2121 вместо 21 чтобы избежать конфликтов)
    address = ('0.0.0.0', 2121)
    
    # Создаем и запускаем сервер
    server = FTPServer(address, handler)
    
    # Лимиты для защиты от DoS
    server.max_cons = 256
    server.max_cons_per_ip = 5
    
    print("="*50)
    print("Уязвимый FTP сервер успешно запущен")
    print(f"Адрес: ftp://localhost:2121")
    print("Логин: anonymous")
    print("Пароль: любой (можно оставить пустым)")
    print("="*50)
    print("Для остановки сервера нажмите Ctrl+C")
    print("="*50)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен")
    finally:
        server.close_all()

if __name__ == "__main__":
    run_ftp_server()