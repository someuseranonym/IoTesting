from NetAnalizer import *
from TypeGetter import *
from GraphicalInterface import *
from tkinter import *
from Vulnerabilities.VulnerabilityChecker import *
from subprocess import check_output  # Добавлен импорт

device_str_name = {DeviceType.Lamp: 'Лампа', DeviceType.Socket: 'Розетка', DeviceType.Thermostat: 'Термостат',
                   DeviceType.Printer: 'Принтер', DeviceType.Sensor: 'Датчик', DeviceType.light_switch: 'Выключатель',
                   DeviceType.Counter: 'Счётчик', DeviceType.Lock: 'Замок', DeviceType.Camera: 'Камера',
                   DeviceType.Skip: 'Пропустить устройство'}

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
    devices = interface.data
    print(interface.data)
    print(devices)
    for i in devices:
        i['type'] = i['тип']
        for j in device_str_name:
            if device_str_name[j] == i['type']:
                i['type'] = j
    print(devices)
    
    # Проверка уязвимостей
    vuln_checker = VulnerabilityChecker()
    vulnerabilities = vuln_checker.check(devices)
    
    # Отображение результатов
    interface.next_button1.pack_forget()
    interface.table_devices.pack_forget()
    
    # Формирование тестовых данных (замените на реальные результаты)
    print(vulnerabilities)
    interface.show_vulns_table(vulnerabilities)

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
