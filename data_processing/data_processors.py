from data_processing.data_writers import DataWriterJson


class Process():
    def __init__(self, fw_data):
        self.__fw_data = fw_data
        self.data_writers = {
            'json': DataWriterJson
        }
    
    def __call__(self):
        pass

    def get_data(self):
        return self.__fw_data
    
    def write_data_to_file(self, data_type, path):
        writer = self.data_writers[data_type]()
        writer.write(path, self.__fw_data)


class ProcessSRX(Process):
    def __init__(self, fw_data):
        super().__init__(fw_data)

