class Process():
    def __init__(self, conf_file):
        self.__fw_data = {}
        self.__conf_file = conf_file
    
    def __call__(self):
        pass

    def get_data(self):
        return self.__fw_data
    

class ProcessSRX(Process):
    def __init__(self, conf_file):
        super().__init__(conf_file)

