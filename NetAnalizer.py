from socket import socket, AF_INET, SOCK_DGRAM
from subprocess import check_output
import scapy.all as sc
import requests
import argparse

import mac_vendor_lookup
class VendorLookup:
    def __init__(self, api_key=None):
        self.api_url = "https://api.macvendors.com/"
        self.api_key = api_key  # Optional API key, if needed.  Some services may require this.

    def get_vendor_by_mac1(self, mac_address):
        """Looks up the vendor for a given MAC address."""
        try:
            url = self.api_url + mac_address  # The simplest API just appends the MAC
            if self.api_key:
                url += f"?apiKey={self.api_key}"  # Add API key if required

            response = requests.get(url)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            if response.status_code == 200:
                return response.text.strip()  # Return the vendor name
            else:
                return None  # Or handle other status codes as needed

        except requests.exceptions.RequestException as e:
            return None
        except Exception as e:
            return None
    def get_vendor_by_mac(self, mac_address):
        try:
            vendor = mac_vendor_lookup.MacLookup().lookup("00:1A:1E:07:BF:06")
        except mac_vendor_lookup.exceptions.MacLookupError as e:
            pass
    def find_vendors(self, ip_mac_list):
        """Takes list of MAC and IP and returns updated dict"""
        for ipmac in ip_mac_list:
          ipmac['vendor'] = self.get_vendor_by_mac(ipmac['mac'])
        return ip_mac_list
def get_arguments():
    # This will give user a neat CLI
    parser = argparse.ArgumentParser()

    # We need the MAC address
    parser.add_argument("-m", "--macaddress",
                        dest="mac_address",
                        help="MAC Address of the device. "
                        )
    options = parser.parse_args()

    # Check if address was given
    if options.mac_address:
        return options.mac_address
    else:
        parser.error("[!] Invalid Syntax. "
                     "Use --help for more details.")


def get_mac_details(mac_address):
    # We will use an API to get the vendor details
    url = "https://api.macvendors.com/"

    # Use get method to fetch details
    response = requests.get(url + mac_address)
    if response.status_code != 200:
        raise Exception("[!] Invalid MAC Address!")
    return response.content.decode()





def local_ip():
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def get_ip_mac_nework(ip):
    ans = sc.srp(sc.Ether(dst='ff:ff:ff:ff:ff:ff') / sc.ARP(pdst=ip), timeout=1, verbose=False)[0]
    cl = []
    for e in ans:
        cl.append({'ip': e[1].psrc, 'mac': e[1].hwsrc})
    return cl


def print_ip_mac(mac_ip_list):
    print(f"\nMachine in Network:\n\nIP\t\t\t\t\tMAC-address\n{'-' * 41}")
    for client in mac_ip_list:
        print(f'{client["ip"]}\t\t{client["mac"]}')