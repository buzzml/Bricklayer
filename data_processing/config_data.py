from abc import ABC, abstractmethod
import traceback


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
    pass
