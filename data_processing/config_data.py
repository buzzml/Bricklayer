from abc import ABC, abstractmethod
import traceback
from netmiko import ConnectHandler


class ConfigData(ABC):
    @abstractmethod
    def get(self):
        pass


class ConfigDataTXT(ConfigData):
    def __init__(self, conf_file):
        self.__conf_file = conf_file

    def get(self):
        try:
            with open(self.__conf_file) as file:
                for line in file:
                    yield line
        except OSError as e:
            traceback.print_exc()


class ConfigDataSSH(ConfigData):
    def __init__(self, ip, user, passwd, vendor, port=22):
        self.__device = {
            'device_type': vendor,
            'host': ip,
            'username': user,
            'password': passwd,
            'port': port,        
        }

        self.__get_conf_comms = {
            'fortinet': 'show full-configuration'
        }

        try:
            net_connect = ConnectHandler(**self.__device)
            self.comm = self.__get_conf_comms[vendor]
            self.__output = net_connect.send_command(self.comm)
            self.__output = self.__output.splitlines()
            net_connect.disconnect()
        except Exception as e:
            traceback.print_exc()

    def get(self):
        for line in self.__output:
            yield line