from NetAnalizer import *
from TypeGetter import *
from GraphicalInterface import *
from tkinter import *
from Vulnerabilities.VulnerabilityChecker import *
from subprocess import check_output  # Добавлен импорт

# Константы (должны быть определены где-то в вашем коде)
device_str_name = {}  # Замените на реальный словарь соответствий типов устройств

def get_gateway():
    try:
        com = f'route PRINT 0* | findstr {local_ip}'.split()
        return check_output(com, shell=True).decode('cp866').split()[2]
    except Exception as e:
        print(f"Ошибка при получении шлюза: {e}")
        return "192.168.1.1"  # Возвращаем значение по умолчанию в случае ошибки

# Инициализация
devices = []
local_ip = local_ip()  # Функция local_ip() должна быть определена
gateway = get_gateway()
window = Tk()
interface = GraphicalInterface(window)

def get_vendor(devices):
    vendor_lookup = VendorLookup()
    for device in devices:
        vendor = vendor_lookup.get_vendor_by_mac(device['mac'])
        if vendor is None:
            vendor = vendor_lookup.get_vendor_by_mac1(device['mac'])
        device['vendor'] = vendor
    return devices

def on_next_clicked(event=None):  # Добавлен параметр по умолчанию для совместимости
    print('Next clicked')
    devices = interface.data
    print("Current devices data:", devices)
    
    # Преобразование типов устройств
    for device in devices:
        device_type = device.get('тип') or device.get('type')
        if device_type:
            for key, value in device_str_name.items():
                if value == device_type:
                    device['type'] = key
                    break
    
    print("Processed devices:", devices)
    
    # Проверка уязвимостей
    vuln_checker = VulnerabilityChecker()
    vulnerabilities = vuln_checker.check(devices)
    
    # Отображение результатов
    interface.next_button1.pack_forget()
    interface.table_devices.pack_forget()
    
    # Формирование тестовых данных (замените на реальные результаты)
    data2 = [{
        "№": 1, 
        "ip": '127.0.0.1', 
        "mac": 'adads788', 
        "type": 'switch', 
        "vuln": 'Пример уязвимости',
        "desc": 'Описание уязвимости',
        "threats": 'Потенциальные угрозы',
        'methods': 'Методы защиты'
    }]
    
    interface.show_vulns_table(data2)

def recognize_types(event):
    print('Starting device recognition')
    try:
        # Получение данных сети
        network = f'{local_ip.split(".")[0]}.{local_ip.split(".")[1]}.{local_ip.split(".")[2]}.1/24'
        devices = get_ip_mac_nework(network)
        devices = get_vendor(devices)
        devices = get_all_types(devices)
        
        # Подготовка данных для отображения
        data = [{
            'ip': device['ip'], 
            'mac': device['mac'], 
            'type': device['type']
        } for device in devices]
        
        # Обновление интерфейса
        interface.canvas.pack_forget()
        interface.show_table(data)
        interface.create_next1_btn()
        interface.next_button1.bind("<Button-1>", lambda e: on_next_clicked())
        interface.next_button1.pack(pady=20, side="bottom", anchor="center")
        
    except Exception as e:
        print(f"Ошибка при распознавании устройств: {e}")
        # Здесь можно добавить вывод сообщения об ошибке в интерфейс

# Настройка обработчиков событий
interface.canvas.bind("<Button-1>", recognize_types)
interface.canvas.pack(fill=BOTH, expand=True)

# Запуск главного цикла
window.mainloop()
