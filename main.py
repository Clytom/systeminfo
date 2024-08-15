from typing import Dict
import wmi
import psutil
import socket
import platform
import requests
from nmap import PortScanner
import pywifi
import hashlib
import sqlite3
import usb


class systemInfo:
    def __init__(self):
        self.localhostip = socket.gethostbyname(socket.gethostname())
    def hardware(self) -> Dict:
        wmi_info = wmi.WMI()
        cpu_info = wmi_info.Win32_Processor()
        # cpu 信息集合
        cpu_main = {}
        for cpu in cpu_info:
            cpu_id = cpu.ProcessorId.strip()
            cpu_name = cpu.Name
            cpu_cores = cpu.NumberOfCores
            cpu_processors = cpu.NumberOfLogicalProcessors
            cpu_description = cpu.Description
            cpu_MaxClockSpeed = cpu.MaxClockSpeed
            cpu_DataWidth = cpu.DataWidth
            cpu_main["id"] = cpu_id
            cpu_main["name"] = cpu_name
            cpu_main["cores"] = cpu_cores
            cpu_main["processor"] = cpu_processors
            cpu_main["description"] = cpu_description
            cpu_main["maxClockSpeed"] = cpu_MaxClockSpeed
            cpu_main["dataWidth"] = cpu_DataWidth
        # 主板集合
        mainboard = {}
        mainboard_info = wmi_info.Win32_ComputerSystem()[0]
        # 制造厂商
        mainboard_Manufacturer = mainboard_info.Manufacturer
        # 主机型号
        mainboard_Model = mainboard_info.Model
        baseboard_info = wmi_info.Win32_BaseBoard()[0]
        # ID
        baseboard_uuid = baseboard_info.qualifiers['UUID'][1:-1]
        baseboard_SerialNumber = baseboard_info.SerialNumber
        # 主板型号
        baseboard_name = mainboard_Manufacturer + ' ' + baseboard_info.Product
        mainboard["Model"] = mainboard_Manufacturer + ' ' + mainboard_Model
        mainboard["SerialNumber"] = baseboard_SerialNumber
        mainboard["UUID"] = baseboard_uuid
        mainboard["Name"] = baseboard_name
        # 硬盘分区
        physical_memory = psutil.virtual_memory()
        memory_info = {
            "总内存": f"{physical_memory.total/(1024**3):.2f}GB",
            "已使用内存": f"{physical_memory.used/(1024**3):.2f}GB",
            "可用运行内存": f"{physical_memory.free/(1024**3):.2f}GB",
        }
        disk_list = []
        disks = wmi_info.Win32_DiskDrive()
        for disk in disks:
            disk_info = {}
            disk_info["Caption"] = disk.Caption
            disk_info["id"] = disk.DeviceID
            if int(disk.Size)/(1024**3) > 1024:
                disk_info["Size"] = f"{int(disk.Size)/(1024**4):.2f}TB"
            else:
                disk_info["Size"] = f"{int(disk.Size) / (1024 ** 3):.2f}GB"
            disk_info["Model"] = disk.Model
            disk_info["SerialNumber"] = disk.SerialNumber.strip()
            disk_list.append(disk_info)
        memory = 0
        PhysicalMemory = wmi_info.Win32_PhysicalMemory()
        for i in PhysicalMemory:
            memory+=int(i.Capacity)/(1024**3)
        nets = wmi_info.Win32_NetworkAdapter()
        net_list = []
        for net in nets:
            data = {}
            data['MACAddress'] = net.MACAddress
            data['Name'] = net.Name
            data['DeviceID'] = net.DeviceID
            data['AdapterType'] = net.AdapterType
            data['Speed'] = net.Speed
            net_list.append(data)
        # 屏幕信息
        desktop = wmi_info.Win32_DesktopMonitor()
        for m in desktop:
            print(m.PNPDeviceID)
        max_main = {
            "cpu":cpu_main,
            "mainboard":mainboard,
            "memory_info":memory_info,
            "disk_info":disk_list,
            "memory":memory,
            "nets":net_list
        }
        return max_main
    @staticmethod
    def system() -> Dict:
        data = {}
        ip = socket.gethostbyname(socket.gethostname())
        computer_name = socket.gethostname()
        operating_system = platform.platform()
        release = platform.release()
        python_version = platform.python_version()
        data['IP'] = ip
        data['ComputerName'] = computer_name
        data['OperatingSystem'] = operating_system
        data['Release'] = release
        data['PythonVersion'] = python_version
        return data
    def network(self) -> Dict:
        try:
            response = requests.get('https://api.ipify.org?format=json')
            ip = response.json()['ip']
            api_url = f"http://ip-api.com/json/{ip}"
            try:
                response = requests.get(api_url)
                response.raise_for_status()
                data = response.json()
                location = {
                    "IP": ip,
                    'Country': data.get('country'),
                    'Province': data.get('regionName'),
                    'City': data.get('city'),
                }
                return location
            except requests.exceptions.RequestException as e:
                return None
            except requests.exceptions.ConnectionError:
                return None
        except requests.exceptions.ConnectionError:
            return None
    def scan(self):
        nm = PortScanner()
        nm.scan("192.168.56.1", "0-1000")
        for host in nm.all_hosts():
            ip = nm[host].hostname()
            state = nm[host].state()
            print(f"ip:{ip}, state:{state}")
            for proto in nm[host].all_protocols():
                print(f"protocol:{proto}")
                lport = nm[host][proto].keys()
                for port in lport:
                    print(f"port:{port} \t state:{nm[host][proto][port]['state']}")
    def wifi_scan(self):
        wifi = pywifi.PyWiFi()
        self.iface = wifi.interfaces()[0]
        # iface.disconnect()
        self.iface.scan()
        scan_results = self.iface.scan_results()
        net_len = len(scan_results)
        print(f"网络扫描结果{net_len}条")
        for result in scan_results:
            if result.ssid:
                print(result.ssid, result.key, result.id, result.auth, result.bssid, result.cipher)
    def wifi_disconnect(self):
        self.iface.disconnect()

def RunAuto():
    system = systemInfo.system()
    print(system)
    info = systemInfo()
    print(info.network())
    print(info.hardware())
    info.scan()
    info.wifi_scan()

if __name__ == '__main__':
    RunAuto()