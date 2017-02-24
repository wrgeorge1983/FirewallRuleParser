"""
utils.py
"""
__author__ = 'William George'

import json
import ipaddress

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
        ipaddress.ip_address(text.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

def is_ip_network(text):
    try:
        ipaddress.ip_network(text.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def instance_in(obj, classes):
    for cls in classes:
        if isinstance(obj, cls):
            return True
    return False


class IPEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ipaddress._IPAddressBase):
            return {
                '__class__': obj.__class__.__name__,
                'value': str(obj)
            }
        return super().default(self, obj)


def as_IP(dct):
    if '__class__' in dct:
        classes = {
            'IPv4Address': ipaddress.IPv4Address,
            'IPv4Network': ipaddress.IPv4Network,
            'IPv6Address': ipaddress.IPv6Address,
            'IPv6Network': ipaddress.IPv6Network
        }
        cls = classes.get(dct['__class__'])
        if cls is None:
            raise NotImplementedError
        return cls(dct['value'])
    return dct
