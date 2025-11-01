from data_processing.data_processors import ProcessSRX
from data_processing.parsers import ParserSrxSets
from data_processing.config_data import ConfigDataTXT
from data_processing.data_writers import DataWriterJson


class Generate():
    vendors_objs = {}

    def __init__(self):
        self.__conf_data_getters = {'txt': ConfigDataTXT}
        self.__parsers = {'srx sets': ParserSrxSets}
        self.__data_writers = {'json': DataWriterJson}

    def __call__(self, input_data_type, parser_type, config_getter_args):
        conf_getter = self.__conf_data_getters[input_data_type]
        conf_getter = conf_getter(**config_getter_args) #obj init
        
        parser = self.__parsers[parser_type]
        parser = parser(conf_getter) #obj init
        parser.run()

        hostname, fwdata = parser.get_data()
        return hostname, fwdata

    def write_data_to_file(self, fw_data, path, data_type):
        writer = self.__data_writers[data_type]() #obj init
        writer.write(path, fw_data)



args_generate = {
    'input_data_type': 'txt',
    'parser_type': 'srx sets',
    'config_getter_args': {
        'conf_file': r'/home/obojetnie/Projekty_Python/Bricklayer/config_files/srx_sets_2.txt'
    }
}

generate = Generate()
hostname, fwdata = generate(**args_generate)

args_write = {
    'path': f'/home/obojetnie/Projekty_Python/Bricklayer/config_files/{hostname}.json',
    'data_type': 'json',
    'fw_data': fwdata
}

generate.write_data_to_file(**args_write)
