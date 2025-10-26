from data_processing.data_processors import ProcessSRX
from data_processing.parsers import ParserSrxSets
from data_processing.config_data import ConfigDataTXT


class Generate():
    vendors_objs = {}

    def __init__(self, **kwds):
        Generate.vendors_objs = kwds
        print(Generate.vendors_objs)

    def __call__(self, **kwds):
        pass


conf_data_txt = ConfigDataTXT(r'/home/obojetnie/Projekty_Python/Bricklayer/config_files/srx_sets_2.txt')

parser_srx = ParserSrxSets(conf_data_txt)
parser_srx.run()

hostname, fwdata = parser_srx.get_data()

process_srx = ProcessSRX(fwdata)
process_srx.write_data_to_file('json', f'/home/obojetnie/Projekty_Python/Bricklayer/config_files/{hostname}.json')


