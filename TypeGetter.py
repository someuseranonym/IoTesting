from enum import Enum


class DeviceType(Enum):
    Camera = 0
    Lamp = 1
    Socket = 2
    Thermostat = 3
    Printer = 4
    Sensor = 5
    light_switch = 6
    Counter = 7
    Lock = 8
    Skip = 9


device_str_name = {DeviceType.Lamp: 'Лампа', DeviceType.Socket: 'Розетка', DeviceType.Thermostat: 'Термостат',
                   DeviceType.Printer: 'Принтер', DeviceType.Sensor: 'Датчик', DeviceType.light_switch: 'Выключатель',
                   DeviceType.Counter: 'Счётчик', DeviceType.Lock: 'Замок', DeviceType.Camera: 'Камера',
                   DeviceType.Skip: 'Пропустить устройство'}

vendor_type = {
    DeviceType.Camera: ['Azure', 'Arecont Vision', 'Acti', 'FlyView', 'Exacq Technologies', 'Vivotek', 'Axis', 'Beward',
                        'JVC',
                        'Dahua', 'IDIS', 'POLYVISION', 'Sony', 'Rvi', 'AXYCAM', 'Kowa', 'Hikvision', 'Samsung',
                        'Panasonic', 'Verkada', 'Geovision', 'Basler', 'Domination', 'QNAP', 'Milestone', 'Mirasys',
                        'intuVision', 'Wizebox', 'Activecam', 'BSP', 'Cornet', 'Evidence', 'Germikom', 'J2000',
                        'ARNEEV' 'Systems', 'Ltv', 'NOVIcam', 'Photo-X', 'QTECH'],
    DeviceType.Lamp: [], DeviceType.Socket: [], DeviceType.Thermostat: [], DeviceType.Printer: [],
    DeviceType.Sensor: [], DeviceType.light_switch: [], DeviceType.Counter: [], DeviceType.Lock: []}


def get_type_by_vendor(vendor):
    for i in [DeviceType.Camera, DeviceType.Lamp, DeviceType.Socket, DeviceType.Thermostat, DeviceType.Printer,
              DeviceType.Sensor, DeviceType.light_switch, DeviceType.Counter, DeviceType.Lock]:
        for j in vendor_type[i]:
            if vendor == None:
                return device_str_name[DeviceType.Skip]
            if j.lower() in vendor.lower():
                return device_str_name[i]
    return device_str_name[DeviceType.Skip]


def get_all_types(deviceLst):
    for i in range(len(deviceLst)):
        deviceLst[i]['type'] = get_type_by_vendor(deviceLst[i]['vendor'])
    return deviceLst
