from copy import deepcopy
import traceback
from misc import is_ipv4_with_mask


class Parser():
    def __init__(self, conf_file):
        self.__conf_file = conf_file

    def __call__(self):
        return self.get_data()

    def __str__(self):
        return f'Parser {self._vendor}'
    
    def _create_fw_data_template(self):
        categories = [
            'fw_rules', 'NATs', 'routes', 
            'addresses', 'address-groups',
            'services', 'service-groups'
        ]
        nat_cats = {'src': {}, 'dst': {}, 'static':{}}
        fw_data_template = {c:{} for c in categories}
        fw_data_template['NATs'] = nat_cats
        return fw_data_template
    
    def get_data(self):
        return self.fw_data
    
    def _open_file(func):
        def wrapper(self, *args, **kwargs):
            try:
                file = open(self.__conf_file)
            except Exception as e:
                traceback.print_exc()
            else:
                func(self, file)
            finally:
                file.close()
        return wrapper


class ParserSRX(Parser):
    def __init__(self, conf_file):
        super().__init__(conf_file)
        self._vendor = 'SRX'
        self.hostname = ''

    def __call__(self):
        self.fw_data = {'root': self._create_fw_data_template()}
        self.__parse_data()

    @Parser._open_file
    def __parse_data(self, file):
        for line in file:
            line = line.strip()
            line = line.split()
            line, logsys = self.__get_ls_and_new_line(line)

            ## Parse:
            ### Firewall Rule:
            if 'security' in line and 'policies' in line:
                self.__parse_fw_rule(line, logsys)
            ### Address:
            elif 'address-book' in line and not 'address-set' in line:
                self.__parse_address(line, logsys)
            ### Address-set:
            elif 'address-book' in line and 'address-set' in line:
                self.__parse_address_set(line, logsys)
            ## Services:
            elif 'applications' in line and 'application' in line:
                self.__parse_app(line, logsys)
            elif 'application-set' in line and 'application':
                self.__parse_app_set(line, logsys)
            ### Hostname:
            elif 'system' in line and 'host-name' in line:
                self.hostname = line[-1]


    ## Extract logical system from line, 
    ## returns tuple(line without logical-system keyword and name, logical-system name)
    def __get_ls_and_new_line(self, line: str) -> tuple[str, str]:
        if line[1] == 'logical-systems':
            logsys = line[2]
            if logsys not in self.fw_data:
                self.fw_data[logsys] = self._create_fw_data_template()
                line = line[:1] + line[3:]
        else:
            logsys = 'root'
        return line, logsys
    
    ## Parse rule to self.fw_data
    def __parse_fw_rule(self, line: list[str], logsys: str):
        rule_name = line[line.index('policy')+1]
        fw_data = self.fw_data[logsys]['fw_rules']
        if rule_name not in fw_data:
            fw_data[rule_name] = self.__fw_rule_data_template()
            rule_data = fw_data[rule_name]
            ## Add source and destination zone:
            if 'global' in line:
                rule_data['src_zone'] = ['any']
                rule_data['dst_zone'] = ['any']
            elif 'from-zone' in line and 'to-zone' in line:
                rule_data['src_zone'] = [line[line.index('from-zone')+1]]
                rule_data['dst_zone'] = [line[line.index('to-zone')+1]]
            else:
                raise Exception('Problem with zones in ParserSRX.__parse_fw_rule')
        else:
            rule_data = fw_data[rule_name]
        
        if 'description' in line:
            desc_indx = line.index('description')
            desc = line[desc_indx+1:]
            desc = ' '.join(desc)
            rule_data['description'] = desc
        elif 'match' in line:
            match_cat = line[line.index('match')+1]
            match_val = line[line.index('match')+2]
            cat_to_key = {
                'from-zone': 'src_zone', 'to-zone': 'dst_zone', 
                'source-address': 'src_IP', 'destination-address': 'dst_IP',
                'application': 'services'
            }
            key = cat_to_key[match_cat]
            if 'any' in rule_data[key]:
                any_index = rule_data[key].index('any')
                rule_data[key].pop(any_index)
            rule_data[key].append(match_val)
        elif 'then' in line:
            if line[-1] in ['permit', 'deny']:
                rule_data['term_action'] = [line[-1]]
            else:
                rule_data['non_term_action'].append(line[-1])
        else:
            raise Exception(f'Firewall Rule command not processed in ParserSRX.__parse_fw_rule, \n {line}')
    
    def __fw_rule_data_template(self) -> dict[str, list[str]]:
        keys = [
            'src_zone', 'dst_zone', 'src_IP', 
            'dst_IP', 'src_NAT', 'dst_NAT',
            'term_action', 'description', 
            'services', 'non_term_action'
        ]
        return {key:[] for key in keys}

    def __parse_address(self, line, logsys):
        addr = line[-1]
        addr_name = line[-2]
        if '-' in addr:
            addr_type = 'range'
            addr = addr.split('-')
        elif is_ipv4_with_mask(addr):
            addr_type = 'address'
        else:
            addr_type = 'fqdn'
        address_data = {
            'type': addr_type,
            'address': addr
        }
        self.fw_data[logsys]['addresses'][addr_name] = address_data

    def __parse_address_set(self, line, logsys):
        addr = line[line.index('address')+1]
        set_name = line[line.index('address-set')+1]
        if set_name not in self.fw_data[logsys]['address-groups']:
            self.fw_data[logsys]['address-groups'][set_name] = [addr]
        else:
            self.fw_data[logsys]['address-groups'][set_name].append(addr)
    
    def __parse_app(self, line, logsys):
        app_name = line[line.index('application')+1]
        key = line[line.index('application')+2]
        val = line[line.index('application')+3]
        if app_name not in self.fw_data[logsys]['services']:
            self.fw_data[logsys]['services'][app_name] = {}
        self.fw_data[logsys]['services'][app_name][key] = val
    
    def __parse_app_set(self, line, logsys):
        set_name = line[line.index('application-set')+1]
        app_name = line[line.index('application')+1]
        if set_name not in self.fw_data[logsys]['service-groups']:
            self.fw_data[logsys]['service-groups'][set_name] = []
        self.fw_data[logsys]['service-groups'][set_name].append(app_name)

parser_srx = ParserSRX(r'F:\Programowanie\Bricklayer\config_files\srx.txt')
parser_srx()


