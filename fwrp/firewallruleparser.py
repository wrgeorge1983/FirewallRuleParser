"""
firewall_rule_parser.py
"""

import ipaddress

from .utils import lpop, cidr_from_netmask, is_ip_address, is_ip_network

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
log_levels.extend(range(0, 8))


def cli_group(lines):
    current_grp = []
    for line in lines:
        if not line.startswith(' '):
            if current_grp:
                yield current_grp
            if line and not line.startswith('!'):
                current_grp = [line]
        else:
            current_grp.append(line)
    if current_grp:
        yield current_grp


class Parser():

    def __init__(self):
        self.objects = {}
        self.object_groups = {}

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
        elif is_ip_network(t_type):
            r_val['type'] = 'network'
            r_val['target'] = ipaddress.ip_network(t_type)
        elif t_type == 'range':
            r_val['type'] = t_type
            r_val['target'] = target_list
        elif t_type == 'host':
            r_val['type'] = 'network'
            r_val['target'] = ipaddress.ip_network(target_list[0])
        elif t_type in ('subnet', 'network-object'):
            r_val['type'] = 'network'
            r_val.update(Parser.parse_object_target(target_list))
        elif t_type == 'port-object':
            r_val['type'] = 'service'
            t_op, *t_val = target_list
            r_val['target'] = {'op': t_op, 'val': ' '.join(t_val)}
        elif t_type in ('service', 'service-object'):
            s_type = lpop(target_list)
            if s_type == 'object':
                r_val['type'] = 'object'
                r_val['target'] = lpop(target_list)
            else:
                r_val['type'] = 'service'
                r_val['protocol'] = s_type
                if s_type == 'icmp':
                    try:
                        r_val['target'] = {'op': 'eq', 'val': target_list[0]}
                    except IndexError:
                        r_val['target'] = {'op': 'eq', 'val': 'any'}
                else:
                    _ = lpop(target_list)
                    t_op, *t_val = target_list
                    r_val['target'] = {'op': t_op, 'val': ' '.join(t_val)}
        elif t_type == 'icmp-object':
            r_val['type'] = 'service'
            r_val['protocol'] = 'icmp'
            r_val['target'] = {'op': 'eq', 'val': lpop(target_list)}
        elif t_type == 'group-object':
            r_val['type'] = 'object-group'
            r_val['target'] = lpop(target_list)
        elif t_type == 'protocol-object':
            r_val['type'] = 'protocol'
            r_val['target'] = lpop(target_list)
        elif t_type == 'description':
            return None
        elif t_type in ('port-object', 'service-object', 'icmp-object',
                        'group-object', 'protocol-object'):
            r_val['target'] = 'Not Implemented'
        else:
            raise ValueError('Invalid object target type: {}'.format(t_type))
        return r_val

    @staticmethod
    def parse_object(object_lines):
        r_val = {}
        try:
            _, o_type, o_name = object_lines[0].split()
        except ValueError:
            _, o_type, o_name, o_protocol = object_lines[0].split()
            r_val['protocol'] = o_protocol
        r_val['object'] = o_name
        r_val['target'] = [Parser.parse_object_target(line.split())
                           for line in object_lines[1:]]
        r_val['target'] = [t for t in r_val['target'] if t is not None]
        return r_val

    @staticmethod
    def parse_ruleset(ruleset_text):
        ruleset_lines = [line for line in ruleset_text.splitlines() if line]
        ruleset_grps = cli_group(ruleset_lines)
        for grp in ruleset_grps:
            if grp[0].startswith('object'):
                yield Parser.parse_object(grp)
            elif len(grp) > 1:
                raise ValueError(
                    'invalid CLI Group in ruleset_text: {}'.format('\n'.join(grp)))
            elif grp[0].startswith('access-list'):
                yield Parser.parse_ace(grp[0].split())


def get_ruleset():
    with open('testruleset.cfg') as fil:
        ruleset = fil.read()
    return ruleset


def run_ruleset():
    import json
    rs = get_ruleset()
    parsed = Parser.parse_ruleset(rs)
    with open('rules_out.txt', 'w') as fil:
        fil.write(json.dumps(list(parsed), default=lambda o: str(o), indent=4 ))


def main():
    pass

if __name__ == '__main__':
    main()