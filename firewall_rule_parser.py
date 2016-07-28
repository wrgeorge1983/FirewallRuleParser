"""
firewall_rule_parser.py
"""

import ipaddress
import math

test_rules = [
    'access-list 123 permit tcp any host 10.20.30.40 eq 80'
]


def cidr_from_netmask(netmask):
    """
    Give the subnet mask length for a given netmask.

    Note:  This only lightly validates the netmask, this will not catch errors including but not limited to:
        0.255.255.255
        255.254.255.0
        etc...

    :param netmask: a valid netmask of the form 255.255.255.0
    :return:
    """
    bits = 0
    octets = netmask.split('.')
    valid_octets = [
        0,
        128,
        192,
        224,
        240,
        248,
        252,
        254,
        255
    ]
    if len(octets) != 4 or any(octet not in valid_octets for octet in octets):
        raise ValueError('Invalid netmask "{}"'.format(netmask))

    bits = sum(index for index, _ in enumerate(valid_octets))
    return bits


class Parser():

    def __init__(self):
        pass

    def parse_rule(self, rule_text):
        rule_text = rule_text.strip()
        rule_list = rule_text.split()
        if len(rule_list) < 6:
            raise ValueError('Invalid rule_text "{}"'.format(rule_text))

        rule_type = rule_list[0]
        if rule_type == 'access-list':
            acl_name, acl_action, acl_proto = rule_list[1:4]

    def parse_target(self, target_text):
        target_text = target_text.strip()
        target_list = target_text.split()
        t_len = len(target_list)
        if t_len == 1:
            if target_text == 'any':
                return 'any'
            try:
                return ipaddress.IPv4Address(target_text)
            except ipaddress.AddressValueError:
                pass


def main():
    pass

if __name__ == '__main__':
    main()