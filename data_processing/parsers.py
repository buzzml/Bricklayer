from copy import deepcopy
import traceback
from data_processing.isip import is_ipv4_with_mask, is_ipv4_without_mask
#from .isip import is_ipv4_with_mask, is_ipv4_without_mask #tests
import re


class Parser():
    def __init__(self, conf_file):
        self.__conf_file = conf_file
        self._hostname = ''
        self._fw_data = {}

    def __call__(self):
        return self.get_data()

    def __str__(self):
        return f'Parser {self.__vendor}'
    
    def _create_fw_data_template(self):
        categories = [
            'fw rules', 'NATs', 'routes', 
            'addresses', 'address-groups',
            'services', 'service-groups',
            'interfaces'
        ]
        nat_cats = {'src': {}, 'dst': {}, 'static':{}}
        route_cats = {'static': [], 'direct': [], 'local': []}
        fw_data_template = {c:{} for c in categories}
        fw_data_template['routes'] = route_cats
        fw_data_template['NATs'] = nat_cats
        return fw_data_template
    
    def get_data(self):
        return self._hostname, self._fw_data
    
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
        self.__vendor = 'SRX'

    def __call__(self):
        self._fw_data = {'root': self._create_fw_data_template()}
        self.__parse_data()
        return self._fw_data

    def __identify_comm(self, comm: str) -> str:
        comm_type_to_pattern = {
            'fw rules': 'set .*security policies .* policy .*',
            'address-groups': 'set .*security .* address-set .*',
            'addresses': 'set .*security .* address .*',
            'services': 'set .*applications application .*',
            'service-groups': 'set .*application-set .* application .*',
            'static route': 'set .*routing-options static route .*',
            'interface IPv4': 'set .*interfaces .* unit .* family inet address .*',
            'intf to Routing Instance': 'set .*routing-instances .* interface .*',
            'static NAT': 'set .*security nat static rule-set',
            'hostname': 'set system host-name .*',
        }

        result = ''
        for comm_type in comm_type_to_pattern.keys():
            pattern = comm_type_to_pattern[comm_type]
            if re.match(pattern, comm):
                result = comm_type
                break
        return result


    @Parser._open_file
    def __parse_data(self, file):
        for line in file:
            if 'set' not in line: 
                continue
            line = line.strip()
            line = line.split()
            line, logsys = self.__get_ls_and_new_line(line)

            ## Parse:
            ### Firewall Rule:
            if 'security' in line and 'policies' in line:
                result = self.__parse_fw_rule(line, logsys)
                rule_name, key, val = result
                self.__add_fw_rule_to_fw_data(logsys, rule_name, key, val, line)
            ### Address:
            elif 'address-book' in line and not 'address-set' in line:
                addr_name, address_data = self.__parse_address(line, logsys)
                self._fw_data[logsys]['addresses'][addr_name] = address_data
            ### Address-set:
            elif 'address-book' in line and 'address-set' in line:
                set_name, addr = self.__parse_address_set(line, logsys)
                if set_name not in self._fw_data[logsys]['address-groups']:
                    self._fw_data[logsys]['address-groups'][set_name] = [addr]
                else:
                    self._fw_data[logsys]['address-groups'][set_name].append(addr)
            ### Services:
            elif 'applications' in line and 'application' in line:
                app_name, key, val = self.__parse_app(line, logsys)
                if app_name not in self._fw_data[logsys]['services']:
                    self._fw_data[logsys]['services'][app_name] = {}
                self._fw_data[logsys]['services'][app_name][key] = val
            ### Service-Groups:
            elif 'application-set' in line and 'application':
                set_name, app_name = self.__parse_app_set(line, logsys)
                if set_name not in self._fw_data[logsys]['service-groups']:
                    self._fw_data[logsys]['service-groups'][set_name] = []
                self._fw_data[logsys]['service-groups'][set_name].append(app_name)
            ### Static Routes:
            elif {'routing-options', 'static', 'route'}.issubset(set(line)):
                key, next_hop, dest_ip = self.__parse_static_route(line, logsys)
                route_data = {'dest IP': dest_ip}
                route_data[key] = next_hop
                self._fw_data[logsys]['routes']['static'].append(route_data)
            ### Local Routes:
            elif {'interfaces', 'family', 'inet'}.issubset(set(line)):
                intf_data = self._fw_data[logsys]['interfaces']
                int_ip, int_nbr, unit = self.__parse_intf_local_route(line)
                if int_nbr not in intf_data:
                    intf_data[int_nbr] = {}
                intf_data[int_nbr][unit] = {'IP': int_ip}
            ### Static NATs:
            elif {'nat', 'static', 'rule-set'}.issubset(set(line)):
                if 'from' in line and 'zone' in line:
                    self.__stat_nat_src_zone = line[line.index('zone')+1]
                else:
                    static_nats = self._fw_data[logsys]['NATs']['static']
                    nat_rule_name, key, val = self.__parse_static_nat(line, logsys)
                    if nat_rule_name not in static_nats:
                        static_nats[nat_rule_name] = {'src zone': self.__stat_nat_src_zone}
                    static_nats[nat_rule_name][key] = val
            ### Hostname:
            elif 'system' in line and 'host-name' in line:
                self._hostname = line[-1]
        
        ## Clear: just for parsing vars:
        try:
            del self.__stat_nat_src_zone
        except AttributeError as e:
            print(e)

    ## Extract logical system from line, 
    ## returns tuple(line without logical-system keyword and name, logical-system name)
    def __get_ls_and_new_line(self, line: str) -> tuple[str, str]:
        if line[1] == 'logical-systems':
            logsys = line[2]
            if logsys not in self._fw_data:
                self._fw_data[logsys] = self._create_fw_data_template()
                line = line[:1] + line[3:]
        else:
            logsys = 'root'
        return line, logsys
    
    def __add_fw_rule_to_fw_data(
            self, logsys:str, 
            rule_name: str, 
            key: str, 
            val: str,
            line: list[str]
    ):
        if rule_name not in self._fw_data[logsys]['fw rules']:
            rule_data = self.__fw_rule_data_template()
            self._fw_data[logsys]['fw rules'][rule_name] = rule_data
            zones = self.__parse_fw_rule_zones(line)
            rule_data['src_zone'], rule_data['dst_zone'] = zones
        else:
            rule_data = self._fw_data[logsys]['fw rules'][rule_name]
        ## Remove any from global policy, if there is match zone definied :
        if key == 'src_zone' and 'any' in rule_data['src_zone']:
            rule_data['src_zone'].pop(rule_data['src_zone'].index('any'))
        if key == 'dst_zone' and 'any' in rule_data['dst_zone']:
            rule_data['dst_zone'].pop(rule_data['src_zone'].index('any'))
        rule_data[key].append(val)

    def __parse_fw_rule_zones(self, line: list[str]):
        if 'global' not in line:
            src_zones = [line[line.index('from-zone')+1]]
            dst_zones = [line[line.index('to-zone')+1]]
        elif 'global' in line:
            src_zones = ['any']
            dst_zones = ['any']            
        else:
            raise Exception('Problem with zones in ParserSRX.__parse_fw_rule')
        return src_zones, dst_zones

    ## Parse rule to self._fw_data
    def __parse_fw_rule(self, line: list[str], logsys: str):
        rule_name = line[line.index('policy')+1]
        
        if 'description' in line:
            desc_indx = line.index('description')
            desc = line[desc_indx+1:]
            desc = ' '.join(desc)
            result = rule_name, 'description', desc
        elif 'match' in line:
            match_cat = line[line.index('match')+1]
            match_val = line[line.index('match')+2]
            cat_to_key = {
                'from-zone': 'src_zone', 'to-zone': 'dst_zone', 
                'source-address': 'src_IP', 'destination-address': 'dst_IP',
                'application': 'services'
            }
            key = cat_to_key[match_cat]
            result = rule_name, key, match_val

        elif 'then' in line:
            if line[-1] in ['permit', 'deny']:
                result = rule_name, 'term_action', line[-1]
            else:
                result = rule_name, 'non_term_action', line[-1]
        else:
            raise Exception(f'Firewall Rule command not processed in ParserSRX.__parse_fw_rule, \n {line}')
        return result

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
        return addr_name, address_data

    def __parse_address_set(self, line, logsys):
        addr = line[line.index('address')+1]
        set_name = line[line.index('address-set')+1]
        return set_name, addr
    
    def __parse_app(self, line, logsys):
        app_name = line[line.index('application')+1]
        key = line[line.index('application')+2]
        val = line[line.index('application')+3]
        return app_name, key, val
    
    def __parse_app_set(self, line, logsys):
        set_name = line[line.index('application-set')+1]
        app_name = line[line.index('application')+1]
        return set_name, app_name
    
    def __parse_static_route(self, line, logsys):
        dest_ip = line[line.index('route')+1]
        next_hop = line[line.index('next-hop')+1]
        if is_ipv4_without_mask(next_hop):
            key = 'next hop IP'
        else:
            key = 'next hop interface'
        return key, next_hop, dest_ip
    
    def __parse_intf_local_route(self, line):
        get = lambda string: line[line.index(string)+1]
        int_ip = get('address')
        int_numbr = get('interfaces')
        unit = get('unit')
        return int_ip, int_numbr, unit
    
    def __parse_static_nat(self, line, logsys):
        nat_rule_name = line[line.index('rule') + 1]
        if 'match' in line and 'source-address' in line:
            key = 'orginal IP'
            val = line[line.index('source-address')+1]
        elif 'then' in line and 'static-nat' in line:
            key = 'NATed IP'
            val = line[line.index('static-nat')+1]
        return nat_rule_name, key, val


