from copy import deepcopy
from data_processing.isip import is_ipv4_with_mask, is_ipv4_without_mask
import re
from data_processing.config_data import ConfigData
from abc import ABC, abstractmethod


class Parser(ABC):
    def __init__(self, conf_data: ConfigData):
        self._conf_data = conf_data
        self._hostname = ''
        self._fw_data = {}
        self._conf_type = ''

    @abstractmethod
    def run(self):
        pass

    def __str__(self):
        name = f'Parser {self.__vendor}'
        if bool(self._conf_type):
            name += f' {self._conf_type}'
        return name
    
    def _create_fw_data_template(self):
        categories = [
            'fw rules', 'NATs', 'routes', 
            'addresses', 'address-groups',
            'services', 'service-groups',
            'interfaces',
        ]
        nat_cats = {'src': {}, 'dst': {}, 'static':{}}
        route_cats = {'static': [], 'direct': [], 'local': []}
        fw_data_template = {c:{} for c in categories}
        fw_data_template['routes'] = route_cats
        fw_data_template['NATs'] = nat_cats
        return fw_data_template
    
    def _fw_rule_data_template(self) -> dict[str, list[str]]:
        keys = [
            'src_zone', 'dst_zone', 'src_IP', 
            'dst_IP', 'src_NAT', 'dst_NAT',
            'term_action', 'description', 
            'services', 'non_term_action',
            'status'
        ]
        return {key:[] for key in keys}
    
    def get_data(self):
        return self._hostname, self._fw_data


class ParserSrx(Parser, ABC):
    def __init__(self, conf_data: ConfigData):
        super().__init__(conf_data)
        self.__vendor = 'SRX'
    
## For parsing in Set-style config; commands starting with set keyword:
class ParserSrxSets(ParserSrx):
    def __init__(self, conf_data: ConfigData):
        super().__init__(conf_data)
        self._conf_type = 'Set-style'

    def run(self):
        self._fw_data = {'root': self._create_fw_data_template()}
        self.__parse_data()
        return self._fw_data

    def __identify_comm(self, comm: str) -> str:
        comm_type_to_pattern = {
            'fw rules': '^set (?!groups ).*security policies .* policy .*',
            'address-groups': '^set (?!groups ).*security .* address-set .*',
            'addresses': '^set (?!groups ).*security .* address .*',
            'services': '^set (?!groups ).*applications application .*',
            'service-groups': '^set (?!groups ).*application-set .* application .*',
            'static route': '^set (?!groups ).*routing-options static route .*',
            'interface IPv4': '^set (?!groups ).*interfaces .* unit .* family inet address .*',
            'intf to Routing Instance': '^set (?!groups ).*routing-instances .* interface .*',
            'static NAT': '^set (?!groups ).*security nat static rule-set',
            'hostname': 'set system host-name .*',
        }

        result = ''
        for comm_type in comm_type_to_pattern.keys():
            pattern = comm_type_to_pattern[comm_type]
            if re.match(pattern, comm):
                result = comm_type
                break
        return result

    def __parse_data(self):
        for line in self._conf_data.get():
            if 'set' not in line: 
                continue
            line = line.strip()
            comm_splited = line.split()
            comm_splited, logsys = self.__get_ls_and_new_comm_splited(comm_splited)

            ## Parse:
            match self.__identify_comm(line):
            ### Firewall Rule:
                case 'fw rules':
                    result = self.__parse_fw_rule(comm_splited, logsys)
                    rule_name, key, val = result
                    self.__add_fw_rule_to_fw_data(logsys, rule_name, key, val, comm_splited)
                ### Address:
                case 'addresses':
                    addr_name, address_data = self.__parse_address(comm_splited, logsys)
                    self._fw_data[logsys]['addresses'][addr_name] = address_data
                ### Address-set:
                case 'address-groups':
                    set_name, addr = self.__parse_address_set(comm_splited, logsys)
                    if set_name not in self._fw_data[logsys]['address-groups']:
                        self._fw_data[logsys]['address-groups'][set_name] = [addr]
                    else:
                        self._fw_data[logsys]['address-groups'][set_name].append(addr)
                ### Services:
                case 'services':
                    app_name, key, val = self.__parse_app(comm_splited, logsys)
                    if app_name not in self._fw_data[logsys]['services']:
                        self._fw_data[logsys]['services'][app_name] = {}
                    self._fw_data[logsys]['services'][app_name][key] = val
                ### Service-Groups:
                case 'service-groups':
                    set_name, app_name = self.__parse_app_set(comm_splited, logsys)
                    if set_name not in self._fw_data[logsys]['service-groups']:
                        self._fw_data[logsys]['service-groups'][set_name] = []
                    self._fw_data[logsys]['service-groups'][set_name].append(app_name)
                ### Static Routes:
                case 'static route':
                    key, next_hop, dest_ip = self.__parse_static_route(comm_splited, logsys)
                    route_data = {'dest IP': dest_ip}
                    route_data[key] = next_hop
                    self._fw_data[logsys]['routes']['static'].append(route_data)
                ### Local Routes:
                case 'interface IPv4':
                    intf_data = self._fw_data[logsys]['interfaces']
                    int_ip, int_nbr, unit = self.__parse_intf_local_route(comm_splited)
                    if int_nbr not in intf_data:
                        intf_data[int_nbr] = {}
                    intf_data[int_nbr][unit] = {'IP': int_ip}
                ### Static NATs:
                case 'static NAT':
                    if 'from' in comm_splited and 'zone' in comm_splited:
                        self.__stat_nat_src_zone = comm_splited[comm_splited.index('zone')+1]
                    else:
                        static_nats = self._fw_data[logsys]['NATs']['static']
                        nat_rule_name, key, val = self.__parse_static_nat(comm_splited, logsys)
                        if nat_rule_name not in static_nats:
                            static_nats[nat_rule_name] = {'src zone': self.__stat_nat_src_zone}
                        static_nats[nat_rule_name][key] = val
                ### Hostname:
                case 'hostname':
                    self._hostname = comm_splited[-1]
        
        ## Clear: just for parsing vars:
        try:
            del self.__stat_nat_src_zone
        except AttributeError as e:
            print(e)

    ## Extract logical system from comm_splited, 
    ## returns tuple(comm_splited without logical-system keyword and name, logical-system name)
    def __get_ls_and_new_comm_splited(self, comm_splited: str) -> tuple[str, str]:
        if comm_splited[1] == 'logical-systems':
            logsys = comm_splited[2]
            if logsys not in self._fw_data:
                self._fw_data[logsys] = self._create_fw_data_template()
                comm_splited = comm_splited[:1] + comm_splited[3:]
        else:
            logsys = 'root'
        return comm_splited, logsys
    
    def __add_fw_rule_to_fw_data(
            self, logsys:str, 
            rule_name: str, 
            key: str, 
            val: str,
            comm_splited: list[str]
    ):
        zones = self.__parse_fw_rule_zones(comm_splited)
        rule_name = f'{zones[0]};{zones[1]};{rule_name}'
        # Rule name with source and dest zone, 
        # because rules with same exact name can exist in
        # different s_zone-des_zone pairs    

        if rule_name not in self._fw_data[logsys]['fw rules']:
            rule_data = self._fw_rule_data_template()
            self._fw_data[logsys]['fw rules'][rule_name] = rule_data
            zones = self.__parse_fw_rule_zones(comm_splited)
            rule_data['src_zone'], rule_data['dst_zone'] = zones
        else:
            rule_data = self._fw_data[logsys]['fw rules'][rule_name]
        ## Remove any from global policy, if there is match zone definied :
        if key == 'src_zone' and 'any' in rule_data['src_zone']:
            rule_data['src_zone'].pop(rule_data['src_zone'].index('any'))
        if key == 'dst_zone' and 'any' in rule_data['dst_zone']:
            rule_data['dst_zone'].pop(rule_data['src_zone'].index('any'))
        rule_data[key].append(val)

    def __parse_fw_rule_zones(self, comm_splited: list[str]):
        if 'global' not in comm_splited:
            src_zones = [comm_splited[comm_splited.index('from-zone')+1]]
            dst_zones = [comm_splited[comm_splited.index('to-zone')+1]]
        elif 'global' in comm_splited:
            src_zones = ['any']
            dst_zones = ['any']            
        else:
            raise Exception('Problem with zones in ParserSRX.__parse_fw_rule')
        return src_zones, dst_zones

    ## Parse rule to self._fw_data
    def __parse_fw_rule(self, comm_splited: list[str], logsys: str):
        rule_name = comm_splited[comm_splited.index('policy')+1]
        
        if 'description' in comm_splited:
            desc_indx = comm_splited.index('description')
            desc = comm_splited[desc_indx+1:]
            desc = ' '.join(desc)
            result = rule_name, 'description', desc
        elif 'match' in comm_splited:
            match_cat = comm_splited[comm_splited.index('match')+1]
            match_val = comm_splited[comm_splited.index('match')+2]
            cat_to_key = {
                'from-zone': 'src_zone', 'to-zone': 'dst_zone', 
                'source-address': 'src_IP', 'destination-address': 'dst_IP',
                'application': 'services'
            }
            if match_cat in cat_to_key:
                key = cat_to_key[match_cat]
            else:
                key = match_cat
            result = rule_name, key, match_val

        elif 'then' in comm_splited:
            if comm_splited[-1] in ['permit', 'deny']:
                result = rule_name, 'term_action', comm_splited[-1]
            else:
                result = rule_name, 'non_term_action', comm_splited[-1]
        else:
            raise Exception(f'Firewall Rule command not processed in ParserSRX.__parse_fw_rule, \n {comm_splited}')
        return result

    def __parse_address(self, comm_splited, logsys):
        addr = comm_splited[-1]
        addr_name = comm_splited[-2]
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
        return addr_name, address_data

    def __parse_address_set(self, comm_splited, logsys):
        addr = comm_splited[comm_splited.index('address')+1]
        set_name = comm_splited[comm_splited.index('address-set')+1]
        return set_name, addr
    
    def __parse_app(self, comm_splited, logsys):
        app_name = comm_splited[comm_splited.index('application')+1]
        key = comm_splited[comm_splited.index('application')+2]
        val = comm_splited[comm_splited.index('application')+3]
        return app_name, key, val
    
    def __parse_app_set(self, comm_splited, logsys):
        set_name = comm_splited[comm_splited.index('application-set')+1]
        app_name = comm_splited[comm_splited.index('application')+1]
        return set_name, app_name
    
    def __parse_static_route(self, comm_splited, logsys):
        dest_ip = comm_splited[comm_splited.index('route')+1]
        next_hop = comm_splited[comm_splited.index('next-hop')+1]
        if is_ipv4_without_mask(next_hop):
            key = 'next hop IP'
        else:
            key = 'next hop interface'
        return key, next_hop, dest_ip
    
    def __parse_intf_local_route(self, comm_splited):
        get = lambda string: comm_splited[comm_splited.index(string)+1]
        int_ip = get('address')
        int_numbr = get('interfaces')
        unit = get('unit')
        return int_ip, int_numbr, unit
    
    def __parse_static_nat(self, comm_splited, logsys):
        nat_rule_name = comm_splited[comm_splited.index('rule') + 1]
        if 'match' in comm_splited and 'source-address' in comm_splited:
            key = 'orginal IP'
            val = comm_splited[comm_splited.index('source-address')+1]
        elif 'then' in comm_splited and 'static-nat' in comm_splited:
            key = 'NATed IP'
            val = comm_splited[comm_splited.index('static-nat')+1]
        return nat_rule_name, key, val


def parsers_factory(vendor, conf_getter):
    match vendor:
        case 'srx_set':
            return ParserSrxSets(conf_getter)