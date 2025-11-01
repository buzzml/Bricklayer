class Process():
    def __init__(self, fw_data):
        self.__fw_data = fw_data
    
    def __call__(self):
        pass

    def get_data(self):
        return self.__fw_data


class ProcessSRX(Process):
    def __init__(self, fw_data):
        super().__init__(fw_data)

