import pytest
from data_processing.parsers import ParserSrxSets

## Abbreviation used in comments:
## LS - Logical-System
## RI - Routing Instance


parser_srx = ParserSrxSets('test')

## Test Command Identification Method
### Firewall Rules Commands:
@pytest.mark.parametrize(
    'command',
    [
        (
            'set logical-systems LS1 security policies ' #LS
            'from-zone trust to-zone untrust policy ' 
            'allow-http match source-address any'
        ),
        (
            'set logical-systems LS1 security policies ' #LS
            'from-zone untrust to-zone trust ' 
            'policy deny-all then permit'
        ),
        (
            'set security policies from-zone untrust to-zone ' #no LS
            'trust policy ALLOW-SNATC match source-address INTERNET-ANY'
        ),
        (
            'set security policies global ' #no LS
            'policy allow-web match from-zone trust'
        ),
    ]
)
def test_ident_comm_fw_rules(command):
    tested = parser_srx._ParserSrxSets__identify_comm
    assert tested(command) == 'fw rules'

##########################################################################
### Address Commands:
@pytest.mark.parametrize(
    'command',
    [
        (
            'set security zones security-zone trust ' #no LS, zone
            'address-book address LAN-HOST1 192.168.1.100/32' 
        ),
        (
            'set logical-systems LS1 security zones security-zone ' #LS, zone
            'trust address-book address net1 10.1.1.0/24'
        ),
        (
            'set security address-book global address net1 10.1.1.0/24' #no LS, global
        ),
        (
            'set logical-systems LS1 security address-book ' #LS, global
            'global address net1 10.1.1.0/24'
        ),
    ]
)
def test_ident_comm_addrs(command):
    tested = parser_srx._ParserSrxSets__identify_comm
    assert tested(command) == 'addresses'

##########################################################################
### Address Groups Commands:
@pytest.mark.parametrize(
    'command',
    [
        (
            'set logical-systems LS1 security zones security-zone ' #LS, zones
            'trust address-book address-set TRUST_NETS address net1'
        ),
        (
            'set security address-book global address-set ' #no LS, global
            'SERVERS address WEB_SERVER'
        ),
        (
            'set security zones security-zone trust ' #no LS, zones
            'address-book address-set SERVERS address LAN_RANGE'
        ),
                (
            'set logical-systems LS1 security address-book global ' #LS, global
            'address-set SERVERS address WEB_SERVER'
        ),
    ]
)
def test_ident_comm_addr_set(command):
    tested = parser_srx._ParserSrxSets__identify_comm
    assert tested(command) == 'address-groups'


##########################################################################
### Application Commands:
@pytest.mark.parametrize(
    'command',
    [
        (
            'set logical-systems LS1 applications application ' #LS, protocol
            'APP_HTTP_SSH protocol tcp'
        ),
        (
            'set applications application MyApp destination-port 12345' #no LS, dst-port
        ),
        (
            'set applications application APP-HTTP source-port 0-65535' #no LS, src-port range
        ),
    ]
)
def test_ident_comm_apps(command):
    tested = parser_srx._ParserSrxSets__identify_comm
    assert tested(command) == 'services'

##########################################################################
### Static Route Commands:
@pytest.mark.parametrize(
    'command',
    [
        (
            'set logical-systems LS-TEST routing-instances TEST_ROUTING_INSTANCE ' #LS + RI
            'routing-options static route 0.0.0.0/0 next-hop 192.168.0.1'
        ),
        (
            'set routing-instances TEST_ROUTING_INSTANCE routing-options ' #no LS, RI
            'static route 0.0.0.0/0 next-hop 192.168.0.1'
        ),
        (
            'set routing-options static route 0.0.0.0/0 next-hop 192.168.0.1' #no LS, no RI
        ),
        (
            'set logical-systems LS-TEST routing-options ' #LS, no RI
            'static route 0.0.0.0/0 next-hop 192.168.0.1'
        )
    ]
)
def test_ident_comm_intf_logic(command):
    tested = parser_srx._ParserSrxSets__identify_comm
    assert tested(command) == 'static route'

##########################################################################
### Interface logical address Commands:
@pytest.mark.parametrize(
    'command',
    [
        (
            'set interfaces ge-0/0/2 unit 0 family inet address 203.0.113.1/24' #no LS
        ),
        (
            'set interfaces ge-0/0/2 unit 3121 family inet address 192.168.0.1/16' #no LS
        ),
        (
            'set logical-systems LS interfaces ge-0/0/2 unit 0 ' #LS
            'family inet address 203.0.113.1/24 '
        ),
    ]
)
def test_ident_comm_intf_addr(command):
    tested = parser_srx._ParserSrxSets__identify_comm
    assert tested(command) == 'interface IPv4'

##########################################################################
### Interface to Routing Instance Assignation Commands:
@pytest.mark.parametrize(
    'command',
    [
        (
            'set routing-instances VRF1 interface ge-0/0/1.0' #no LS
        ),
        (
            'set logical-systems LS routing-instances VRF1 interface ge-0/0/1.0' #LS
        ),
    ]
)
def test_ident_comm_intf_to_ri(command):
    tested = parser_srx._ParserSrxSets__identify_comm 
    assert tested(command) == 'intf to Routing Instance'

##########################################################################
### Set Hostname Commands:
@pytest.mark.parametrize(
    'command',
    [
        (
            'set system host-name SRX-SAMPLE'
        ),
    ]
)
def test_ident_comm_hostname(command):
    tested = parser_srx._ParserSrxSets__identify_comm 
    assert tested(command) == 'hostname'

##########################################################################
### Static NAT Commands:
@pytest.mark.parametrize(
    'command',
    [
        (
            'set security nat static rule-set RS-SNATC from zone trust'
        ),
        (
            'set security nat static rule-set RS-SNATC rule '
            'SNATC-HOST1 match source-address 192.168.1.100/32'
        ),
        (
            'set security nat static rule-set RS-SNATC '
            'rule SNATC-HOST1 then static-nat 203.0.113.101'
        ),
        (
            'set logical-systems LS_TEST security nat static '
            'rule-set RS-SNATC rule SNATC-HOST1 then static-nat 203.0.113.101'
        ),
    ]
)
def test_ident_comm_stat_nat(command):
    tested = parser_srx._ParserSrxSets__identify_comm 
    assert tested(command) == 'static NAT'