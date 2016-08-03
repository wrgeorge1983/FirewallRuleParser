"""
firewall_rule_parser.py
"""

import ipaddress
import math

test_rules = [
    'access-list 123 permit tcp any host 10.20.30.40 eq 80'
]

log_levels = [
    'alerts',
    'critical',
    'debugging',
    'emergencies',
    'errors',
    'informational',
    'notifications',
    'warnings'
]
log_levels.extend( range(0, 8))


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
    valid_octets = [
        '0',
        '128',
        '192',
        '224',
        '240',
        '248',
        '252',
        '254',
        '255'
    ]

    octet_values = {octet: value for value, octet in enumerate(valid_octets)}

    if not is_ip_address(netmask):
        raise ValueError('Invalid netmask {}'.format(netmask))

    octets = netmask.split('.')

    try:
        bits = sum(octet_values[octet] for octet in octets)
    except KeyError:
        raise ValueError('Invalid netmask "{}"'.format(netmask))

    return bits


def is_ip_address(text):
    try:
        ipaddress.ip_address(text)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


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
        acl_name, ace_type = ace_list[1:3]

        r_val = {'log': '',
                 'active': True,
                 'text': ' '.join(ace_list)}

        if ace_type == 'remark':
            r_val.update({'type': 'remark',
                          'text': ' '.join(ace_list)})
        elif ace_type == 'extended':
            ace_action, ace_proto = ace_list[3:5]
            r_val.update({
                'acl_type': ace_type,
                'action': ace_action,
                'protocol': ace_proto,
                'acl': acl_name,
            })
            r_val.update(Parser.parse_targets(ace_list[4:]))
            r_ace_list = r_val.pop('remaining_list')

            for index, item in enumerate(r_ace_list):
                if item == 'log':
                    try:
                        n_item = r_ace_list[index + 1]
                        if n_item in log_levels or n_item in ('disable', 'Default'):
                            r_val['log'] = 'log {}'.format(n_item)
                        elif n_item == 'interval':
                            r_val['log'] = 'log {} {}'.format(n_item, r_ace_list[index + 2])
                        else:
                            raise IndexError
                    except IndexError:
                        r_val['log'] = ['log']

                elif item == 'inactive':
                    r_val['active'] = False

            return r_val

    @staticmethod
    def parse_targets(targets_list):

        if 'object' in targets_list[0]:
            s_type = targets_list[0]
        else:
            s_type = lpop(targets_list)

        # staying generic about this because we don't know exactly what format this is yet
        t_A, targets_list = Parser.parse_target(targets_list)
        t_B, targets_list = Parser.parse_target(targets_list)
        try:
            t_C, targets_list = Parser.parse_target(targets_list)
        except ValueError:
            t_C = {'type': 'protocol',
                   'target': s_type}

        if 'object' in s_type:
            svc, src, dst = t_A, t_B, t_C
        else:
            src, dst, svc = t_A, t_B, t_C

        if svc['type'] == 'service':
            svc['type'] = s_type

        return {'src': src, 'dst': dst, 'service': svc, 'remaining_list': targets_list}

    @staticmethod
    def parse_target(target_list):
        o_tl = target_list.copy()
        try:
            t_type = lpop(target_list)
        except ValueError:
            raise ValueError('invalid target_list "{}"'.format(target_list))
        r_val = {'type': t_type}

        if t_type in ('any', 'any4', 'any6'):
            r_val['target'] = t_type

        elif t_type == 'host':
            r_val['type'] = 'network'
            t_target = lpop(target_list)
            r_val['target'] = ipaddress.ip_network('/'.join([t_target, '32']))

        elif t_type in ('object', 'object-group'):
            t_target = lpop(target_list)
            r_val['target'] = t_target

        elif t_type in ('eq', 'lt', 'gt'):
            r_val['type'] = 'service'
            r_val['target'] = {'op': t_type,
                               'val': lpop(target_list)}

        elif is_ip_address(t_type):  # it's an address and mask combination
            t_target = t_type
            r_val['type'] = 'network'
            t_mask = lpop(target_list)
            t_bit_len = cidr_from_netmask(t_mask)
            t_cidr = '/'.join((t_target, str(t_bit_len)))
            r_val['target'] = ipaddress.ip_network(t_cidr, False)

        else:
            raise ValueError('Invalid target list: {}'.format(o_tl))

        return r_val, target_list

    @staticmethod
    def parse_object_target(target_list):
        r_val = {}
        t_type = lpop(target_list)
        if t_type == 'object':
            r_val['type'] = 'object'
            r_val['target'] = lpop(target_list)
        elif is_ip_address(t_type):
            t_target = t_type
            r_val['type'] = 'network'
            t_mask = lpop(target_list)
            t_bit_len = cidr_from_netmask(t_mask)
            t_cidr = '/'.join((t_target, str(t_bit_len)))
            r_val['target'] = ipaddress.ip_network(t_cidr, False)
        elif t_type == 'host':
            r_val['type'] = 'network'
            r_val['target'] = ipaddress.IPv4Network(target_list[0])
        elif t_type in ('subnet', 'network-object'):
            r_val['type'] = 'network'
            r_val.update(Parser.parse_object_target(target_list))
        elif t_type in ('port-object', 'service-object', 'icmp-object',
                        'group-object', 'protocol-object'):
            r_val['target'] = 'Not Implemented'
        else:
            raise ValueError('Invalid object target type: {}'.format(t_type))
        return r_val

    @staticmethod
    def parse_object(object_lines):
        _, o_type, o_name = object_lines[0].split()
        r_val = {'object': o_name}
        r_val.update(Parser.parse_object_target(object_lines[1].split()))
        return r_val


def main():
    pass

if __name__ == '__main__':
    main()