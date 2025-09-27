import pytest
from data_processing.misc import is_ipv4_with_mask


@pytest.mark.parametrize("param1, expected", [
    ('192.168.0.1/25', True),
    ('255.255.255.255 255.255.255.255', True),
    ('0.0.0.0 0.0.0.0', True),
    ('10.10.10.10 255.255.255.255', True),
    ('192.168.0.0 255.255.255.0', True),
    ('1.1.1.1/32', True),
    ('2001:0db8:0000:0000:0000:0000:1428:57ab', False),
    ('192.16.6.6255.255.255.255', False),
    ('www.google.com', False),
    ('10.10.10.10', False),
    ('2001:0db8:0000:0000:0000:0000:1428:57ab', False),
    ('8.8.8.8/34', False),
    ('8.8.256.8/31', False),
    ('8.8.8.8 255.255.0.255', False),
])
def test_isip(param1, expected):
    assert is_ipv4_with_mask(param1) == expected