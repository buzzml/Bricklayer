from data_processing.data_processors import ProcessSRX


class Generate():
    vendors_objs = {}

    def __init__(self, **kwds):
        Generate.vendors_objs = kwds
        print(Generate.vendors_objs)

    def __call__(self, **kwds):
        pass


gen_srx = ProcessSRX()
generate = Generate(srx=gen_srx)