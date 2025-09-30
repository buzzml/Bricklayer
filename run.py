from data_processing.data_processors import ProcessSRX
from data_processing.parsers import ParserSRX


class Generate():
    vendors_objs = {}

    def __init__(self, **kwds):
        Generate.vendors_objs = kwds
        print(Generate.vendors_objs)

    def __call__(self, **kwds):
        pass



parser_srx = ParserSRX(r'F:\Programowanie\Bricklayer\config_files\srx2.txt')
parser_srx()


hostname, fwdata = parser_srx.get_data()
print('\n', fwdata['root']['interfaces'])
