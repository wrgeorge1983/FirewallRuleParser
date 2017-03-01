__author__ = 'William.George'

import unittest

# from ..fwrp.firewallruleparser import lpop, cidr_from_netmask, is_ip_address, cli_group
# from .context.fwrp.firewallruelparser import lpop, cidr_from_netmask, is_ip_address, cli_group
# from .context import fwrp
# from .context.fwrp import firewallruelparser
from fwrp.utils import lpop, cidr_from_netmask, is_ip_address
from fwrp.firewallruleparser import cli_group


class TestLpop(unittest.TestCase):
    def test_lpop(self):
        src_list = [1, 2, 3]
        e_r_val = 1
        e_src_val = [2, 3]

        self.assertEqual(e_r_val, lpop(src_list))
        self.assertEqual(e_src_val, src_list)

    def test_cidr_from_netmask(self):
        tests = [
            ('255.255.255.255', 32),
            ('255.255.255.0', 24),
            ('255.255.0.0', 16),
            ('255.255.128.0', 17)
        ]
        for test in tests:
            t_val, e_r_val = test
            self.assertEqual(e_r_val, cidr_from_netmask(t_val))

    def test_is_ip_address(self):
        tests = [
            ('255.255.255.255', True),
            ('255.255.0.0', True),
            ('0.0.0.0', True),
            ('256.255.255.255', False),
            ('1.1.1.1.1', False),
            (' 1.1.1.1', True),
        ]
        [self.assertEqual(e_out, is_ip_address(src)) for src, e_out in tests]

    def test_cli_group(self):
        src_val = (
            'line1\n'
            'line2\n'
            ' subline2.1\n'
            ' subline2.2\n'
            'line3\n'
            ' subline3.1\n'
        )

        test = (src_val, [
            ['line1'],
            ['line2',
             ' subline2.1',
             ' subline2.2'],
            ['line3',
             ' subline3.1']
        ])

        self.assertEqual(test[1], list(cli_group(test[0].splitlines())))


# if __name__ == '__main__':
#     unittest.main()
