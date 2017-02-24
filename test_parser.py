import unittest
from firewallruleparser import Parser
import ipaddress
__author__ = 'William.George'


class TestParser(unittest.TestCase):
    def test_parse_object_target(self):
        tests = [
            ('host 1.1.1.1',
                {
                    'type': 'network',
                    'target': ipaddress.IPv4Network('1.1.1.1/32')}),
            ('subnet 10.10.10.0 255.255.255.0',
                {
                    'type': 'network',
                    'target': ipaddress.IPv4Network('10.10.10.0/24')}),
            ('network-object object OBJ01',
                {
                    'type': 'object',
                    'target': 'OBJ01'}),
            ('network-object 20.20.0.0 255.255.128.0',
                {
                    'type': 'network',
                    'target': ipaddress.IPv4Network('20.20.0.0/17')}),
            ('port-object eq www',
                {
                    'type': 'service',
                    'target': {'op': 'eq',
                               'val': 'www'}}),
            ('service-object tcp destination eq 2000',
                {
                    'type': 'service',
                    'target': {'op': 'eq',
                               'val': '2000'},
                    'protocol': 'tcp'}),
            ('service-object icmp echo',
                {
                    'type': 'service',
                    'target': {'op': 'eq',
                               'val': 'echo'},
                    'protocol': 'icmp'}),
            ('icmp-object echo-reply',
                {
                    'type': 'service',
                    'target': {'op': 'eq',
                               'val': 'echo-reply'},
                    'protocol': 'icmp'}),
            ('group-object DST_GRP',
                {
                    'type': 'object-group',
                    'target': 'DST_GRP'}),
            ('port-object range 10500 10600',
                {
                    'type': 'service',
                    'target': {'op': 'range',
                               'val': '10500 10600'}}),
            ('protocol-object udp',
                {
                    'type': 'protocol',
                    'target': 'udp'}),
        ]
        for src_val, e_r_val in tests:
            try:
                self.assertEqual(e_r_val, Parser.parse_object_target(src_val.split()))
            except (ValueError):
                self.fail('Failure for src_val "{}"'.format(src_val))

    def test_parse_object(self):
        tests = [
            ('object network OBJ01\n host 1.1.1.1',
                {
                    'type': 'network',
                    'object': 'OBJ01',
                    'target': ipaddress.IPv4Network('1.1.1.1/32')}),
            ('object network OBJ02\n host 2.2.2.2\n description 2nd object',
                {
                    'type': 'network',
                    'object': 'OBJ02',
                    'target': ipaddress.IPv4Network('2.2.2.2/32')})
        ]
        for src_val, e_r_val in tests:
            self.assertEqual(e_r_val, Parser.parse_object(src_val.splitlines()))

    def test_parse_ace(self):
        tests = [
            {
                'text':
                    'access-list test_pz_ext_access_out '
                    'extended permit tcp host 1.1.1.40 host 2.2.2.2 '
                    'object-group web_ports inactive',
                'dst': {
                    'type': 'network',
                    'target': ipaddress.IPv4Network('2.2.2.2/32')},
                'src': {
                    'type': 'network',
                    'target': ipaddress.IPv4Network('1.1.1.40/32')},
                'service': {
                    'type': 'object-group',
                    'target': 'web_ports'},
                'active': False,
                'log': '',
                'protocol': 'tcp',
                'acl': 'test_pz_ext_access_out',
                'acl_type': 'extended',
                'action': 'permit'
            }
        ]
        for test in tests:
            src_val = test['text']
            r_val = Parser.parse_ace(src_val.split())
            for key in test.keys():
                self.assertEqual(test[key], r_val[key])

    def test_parse_target(self):
        tests = [
            ('object-group DM_INLINE_NETWORK_34 10.57.58.44 255.255.255.0 eq 22 log disable',
                {
                    'type': 'object-group',
                    'target': 'DM_INLINE_NETWORK_34'}),
            ('10.57.58.44 255.255.255.0 eq 22 log disable',
                {
                    'type': 'network',
                    'target': ipaddress.IPv4Network('10.57.58.0/24')}),
            ('eq 22 log disable',
                {
                    'type': 'service',
                    'target': {'op': 'eq',
                               'val': '22'}}),
            ('object SRC_OBJ object-group DST_GROUP object-group PORT_GROUP log',
                {
                    'type': 'object',
                    'target': 'SRC_OBJ'}),
            ('host 1.1.1.1',
                {
                    'type': 'network',
                    'target': ipaddress.IPv4Network('1.1.1.1/32')})
        ]
        for src_val, e_r_val in tests:
            r_val, tl = Parser.parse_target(src_val.split())
            for key in e_r_val.keys():
                self.assertEqual(e_r_val[key], r_val[key])

    def test_parse_targets(self):
        tests = [
            ('tcp object-group DM_INLINE_NETWORK_1 10.57.58.44 255.255.255.0 eq 22 log disable',
                {
                    'dst': {
                        'type': 'network',
                        'target': ipaddress.IPv4Network('10.57.58.0/24')},
                    'src': {
                        'type': 'object-group',
                        'target': 'DM_INLINE_NETWORK_1'},
                    'service': {
                        'type': 'tcp',
                        'target': {'op': 'eq',
                                   'val': '22'}},
                    'remaining_list': ['log', 'disable']}),
            ('object-group PORT_GROUP2 object-group SRC_GROUP2 object-group DST_GROUP2 log disable',
                {
                    'dst': {
                        'type': 'object-group',
                        'target': 'DST_GROUP2'},
                    'src': {
                        'type': 'object-group',
                        'target': 'SRC_GROUP2'},
                    'service': {
                        'type': 'object-group',
                        'target': 'PORT_GROUP2'},
                    'remaining_list': ['log', 'disable']}),
            ('tcp object SRC_OBJ3 object-group DST_GROUP3 object-group PORT_GROUP3 log',
                {
                    'dst': {
                        'type': 'object-group',
                        'target': 'DST_GROUP3'},
                    'src': {
                        'type': 'object',
                        'target': 'SRC_OBJ3'},
                    'service': {
                        'type': 'object-group',
                        'target': 'PORT_GROUP3'},
                    'remaining_list': ['log']}),
            ('ip object SRC_OBJ4 object DST_OBJ4',
                {
                    'dst': {
                        'type': 'object',
                        'target': 'DST_OBJ4'},
                    'src': {
                        'type': 'object',
                        'target': 'SRC_OBJ4'},
                    'service': {
                        'type': 'protocol',
                        'target': 'ip'},
                    'remaining_list': []})
        ]
        for src_val, e_r_val in tests:
            r_val = Parser.parse_targets(src_val.split())
            for key in e_r_val.keys():
                self.assertEqual(e_r_val[key], r_val[key])

if __name__ == '__main__':
    unittest.main()