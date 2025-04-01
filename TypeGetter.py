import vendor_type
from vendor_type import *




device_str_name = {DeviceType.Lamp: 'Лампа', DeviceType.Socket: 'Розетка', DeviceType.Thermostat: 'Термостат',
                   DeviceType.Printer: 'Принтер', DeviceType.Sensor: 'Датчик', DeviceType.light_switch: 'Выключатель',
                   DeviceType.Counter: 'Счётчик', DeviceType.Lock: 'Замок', DeviceType.Camera: 'Камера',
                   DeviceType.Skip: 'Пропустить устройство'}


def get_type_by_vendor(vendor):
    if not vendor:
        return device_str_name[DeviceType.Skip]
    for i in vendor_type.keys():
        if vendor.lower() in i.lower():
            return vendor_type[i]
    return device_str_name[DeviceType.Skip]


def get_all_types(deviceLst):
    for i in range(len(deviceLst)):
        deviceLst[i]['type'] = get_type_by_vendor(deviceLst[i]['vendor'])
    return deviceLst
