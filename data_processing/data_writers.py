from abc import ABC, abstractmethod
import json


class DataWriter(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def write(self, path, data):
        pass


class DataWriterExcel(DataWriter):
    pass


class DataWriterJson(DataWriter):
    def write(self, path, data):
        with open(path, 'w') as file:
            json.dump(data, file, indent=4)