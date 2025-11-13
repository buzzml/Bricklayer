from data_processing.data_processors import ProcessSRX
from data_processing.parsers import parsers_factory
from data_processing.config_data import config_data_factory
from data_processing.data_writers import writers_factory


class Generate():
    def __call__(self, input_data_type, vendor, config_getter_args):
        conf_getter = config_data_factory(input_data_type, **config_getter_args)

        parser = parsers_factory(vendor, conf_getter)
        parser.run()

        hostname, fwdata = parser.get_data()
        return hostname, fwdata

    def write_data_to_file(self, fw_data, path, data_type):
        writer = writers_factory(data_type) #obj init
        writer.write(path, fw_data)



args_generate = {
    'input_data_type': 'txt',
    'vendor': 'srx_set',
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
