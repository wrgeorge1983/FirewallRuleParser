"""
firewall_rule_parser.py
"""

import ipaddress
import math

test_rules = [
    'access-list 123 permit tcp any host 10.20.30.40 eq 80'
]


def lpop(src_list):
    try:
        left = src_list[0]
        del src_list[0]
        return left
    except (IndexError, ValueError):
        raise ValueError('cannot left pop src_list "{}"'.format(src_list))

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

    @staticmethod
    def parse_rule(rule_text):
        rule_text = rule_text.strip()
        rule_list = rule_text.split()
        if len(rule_list) < 6:
            raise ValueError('Invalid rule_text "{}"'.format(rule_text))

        rule_type = rule_list[0]
        if rule_type == 'access-list':
            acl_name, acl_action, acl_proto = rule_list[1:4]

    @staticmethod
    def parse_ace(ace_list):
        ace_name = ace_list[1]
        ace_type = ace_list[2]
        ace_text = ' '.join(ace_list[3:])
        if ace_type == 'remark':
            return {'type': 'remark',
                    'text': ' '.join(ace_text)}
        if ace_type == 'extended':
            ace_action, ace_proto = ace_list[3:5]
            ace_src, ace_dst = Parser.parse_targets(ace_list[5:])
            return {'type': 'extended',
                    'text': ' '.join(ace_text),
                    ''}

    @staticmethod
    def parse_targets(targets_list):
        src_target, dst_target = dict(), dict()
        for target in (src_target, dst_target):
            target, targets_list = Parser.parse_target(targets_list)
        return src_target, dst_target

    def parse_target(self, target_list):
        try:
            t_type = lpop(target_list)
        except ValueError:
            raise ValueError('invalid target_list "{}"'.format(target_list))
        r_val = {'type': t_type}
        if t_type in ('any', 'any4', 'any6'):
            return r_val, target_list

        t_target = lpop(target_list)
        if t_type == 'host':
            r_val['target'] = ipaddress.ip_address(t_target)
            return r_val, target_list

        if t_type in ('object', 'object-group'):
            r_val['target'] = t_target
            return r_val, target_list

        # it's an address and mask combination
        t_mask = lpop(target_list)
        t_bit_len = cidr_from_netmask(t_mask)
        t_cidr = '/'.join((t_target, t_bit_len))
        r_val['target'] = ipaddress.ip_network(t_cidr, False)


def main():
    pass

if __name__ == '__main__':
    main()