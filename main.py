from NetAnalizer import *
from TypeGetter import *
from GraphicalInterface import *
from tkinter import *
from Vulnerabilities.VulnerabilityChecker import *

def get_gateway():
    com = f'route PRINT 0* | findstr {local_ip}'.split()
    return check_output(com, shell=True).decode('cp866').split()[2]


devices = []
local_ip = local_ip()
gateway = get_gateway()
# devices = get_device_info()
window = Tk()
interface = GraphicalInterface(window)


def get_vendor(devices):
    vendor_lookup = VendorLookup()
    for i in devices:
        vendor = vendor_lookup.get_vendor_by_mac(i['mac'])
        if vendor == None:
            vendor = vendor_lookup.get_vendor_by_mac1(i['mac'])
        i['vendor'] = vendor
    return devices


def on_next_clicked(event):  # Receive the Treeview and data as parameters
    devices = interface.data
    print(interface.data)
    print(devices)
    for i in devices:
        i['type'] = i['тип']
        for j in device_str_name:
            if device_str_name[j] == i['type']:
                i['type'] = j
    print(devices)

def recognize_types(event):
    print('start recognizing')
    '''devices = get_ip_mac_nework(f'{local_ip.split(".")[0]}.{local_ip.split(".")[1]}.{local_ip.split(".")[2]}.1/24')
    devices = get_vendor(devices)
    devices = get_all_types(devices)
    print(devices)
    data = []
    for i in range(len(devices)):
        data.append({'ip': devices[i]['ip'], 'mac': devices[i]['mac'], 'type': devices[i]['type']})'''
    data = [{'ip': '127.0.0.1', 'mac': 'asfda', 'type': 'Лампа'}, {'ip': '127.0.0.1', 'mac': 'asfda',
                                                                  'type': 'Лампа'},
            {'ip': '127.0.0.2', 'mac': 'asfdda', 'type': 'Лампа'},
            {'ip': '127.0.0.3', 'mac': 'asfd4a', 'type': 'DeviceType.light_switch'},
            {'ip': '127.0.0.1', 'mac': 'asfda', 'type': 'DeviceType.light_switch'}, {'ip': '127.0.0.1', 'mac': 'asfda',
                                                                                    'type': 'Лампа'},
            {'ip': '127.0.0.2', 'mac': 'asfdda', 'type': 'Лампа'},
            {'ip': '127.0.0.3', 'mac': 'asfd4a', 'type': 'DeviceType.light_switch'},
            {'ip': '127.0.0.1', 'mac': 'asfda', 'type': 'DeviceType.light_switch'}, {'ip': '127.0.0.1', 'mac': 'asfda',
                                                                                    'type': 'Лампа'},
            {'ip': '127.0.0.2', 'mac': 'asfdda', 'type': 'Лампа'}]

    interface.canvas.pack_forget()

    interface.show_table(data)
    interface.create_next1_btn()  # Replace with table function
    interface.next_button1.pack(pady=20, side="bottom", anchor="center")


def on_next_clicked():  # Receive the Treeview and data as parameters
    print(123456, 'next clicked')
    interface.next_button1.pack_forget()
    interface.table_devices.pack_forget()
    vuln_checker = VulnerabilityChecker()
    vuln_checker.check(devices)
    # проверка на уязы
    data2 = [{"№": 1, "ip": '127.0.0.1', "mac": 'adads788', "type": 'switch', "vuln": 'name of vulnerability',
             "desc": 'dsajkdjsa;fdjsajfdklsajdfkjsalfkdjsalkfdjksajfdksjafkdjaklfdjskafjdlkasjfkldjsakfdjsaklfjdlksajfdklsjafkldjsakljfdklsajflkdjsalk;fjdlsakfjdlksajflkdjsalkfjdlsakjfdlk;sajljfd',
             "threats": 'dsafkldsa;dfjsakfdksajfkldsajklfdjaskfjd;lsakfjdlksajflkdjaflkdjsaljfd', 'methods': 'dsafdjsakdsajdfklsaj'}]
    interface.show_vulns_table(data2)
    # interface.next_button1 = Button(window, text="Далее",
    #                           command=lambda: on_next_clicked())  # pass only table_devices now
    # interface.next_button1.pack(pady=10)
    """Handles the "Next" button click event."""
    # Access the data from the table, including the dropdown selections.
    ''' updated_data = []
        for item_id in tree.get_children():
            values = tree.item(item_id, 'values')
            if values:
                # Get the dropdown value - use self.data (this is a bug fix)
                row_index = tree.get_children().index(item_id)
                # Check if the dropdown value is correct
                updated_data.append(self.data[row_index])  # Use the correctly modified data

        print("Data from table:", updated_data)
        messagebox.showinfo("Data Confirmation", "Data saved!  See the console output.")'''



def recognize_types(event):
    print('start recognizing')
    devices = get_ip_mac_nework(f'{local_ip.split(".")[0]}.{local_ip.split(".")[1]}.{local_ip.split(".")[2]}.1/24')
    devices = get_vendor(devices)
    devices = get_all_types(devices)
    print(devices)
    data = []
    for i in range(len(devices)):
        data.append({'ip': devices[i]['ip'], 'mac': devices[i]['mac'], 'type': devices[i]['type']})
    '''data = [{'ip': '127.0.0.1', 'mac': 'asfda', 'type': 'Лампа'}, {'ip': '127.0.0.1', 'mac': 'asfda',
                                                                   'type': 'Лампа'},
            {'ip': '127.0.0.2', 'mac': 'asfdda', 'type': 'Лампа'},
            {'ip': '127.0.0.3', 'mac': 'asfd4a', 'type': 'DeviceType.light_switch'},
            {'ip': '127.0.0.1', 'mac': 'asfda', 'type': 'DeviceType.light_switch'}, {'ip': '127.0.0.1', 'mac': 'asfda',
                                                                                     'type': 'Лампа'},
            {'ip': '127.0.0.2', 'mac': 'asfdda', 'type': 'Лампа'},
            {'ip': '127.0.0.3', 'mac': 'asfd4a', 'type': 'DeviceType.light_switch'},
            {'ip': '127.0.0.1', 'mac': 'asfda', 'type': 'DeviceType.light_switch'}, {'ip': '127.0.0.1', 'mac': 'asfda',
                                                                                     'type': 'Лампа'},
            {'ip': '127.0.0.2', 'mac': 'asfdda', 'type': 'Лампа'}]'''

    interface.canvas.pack_forget()

    interface.show_table(data)
    interface.create_next1_btn()  # Replace with table function
    interface.next_button1.bind("<Button-1>", on_next_clicked)
    interface.next_button1.pack(pady=20, side="bottom", anchor="center")



interface.canvas.bind("<Button-1>", recognize_types)
interface.canvas.pack(fill=BOTH, expand=True)  # Pack the canvas
window.mainloop()
