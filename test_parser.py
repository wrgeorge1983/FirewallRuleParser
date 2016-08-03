from unittest import TestCase
from firewallruleparser import Parser
import ipaddress
__author__ = 'William.George'


class TestParser(TestCase):
    def test_parse_rule(self):

        self.fail()

    def test_parse_ace(self):
        tests = [
            (
                'access-list test_pz_ext_access_out '
                'extended permit tcp host 1.1.1.40 host 2.2.2.2 '
                'object-group web_ports inactive',
                {
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
            )
        ]
        for src_val, e_r_val in tests:
            r_val = Parser.parse_ace(src_val.split())
            for key in e_r_val.keys():
                self.assertEqual(e_r_val[key], r_val[key])


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