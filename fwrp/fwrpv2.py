"""
fwrpv2.py
module for manipulating and understanding firewall rulesets
"""
import ipaddress

import attr


@attr.s
class ACLObject(object):
    name = attr.ib()
    type = attr.ib()
    targets = attr.ib()


@attr.s
class ACLObjectCollection(object):
    name = attr.ib()
    objects = attr.ib(default=attr.Factory(list))


def host_to_object(odef):
    value = odef.split()
    ip = ipaddress.IPv4Network('{}/32'.format(value))
    return ACLObject(name=value, type='network', targets=[ip])


def aclo_from_object_definition(object_definition):
    dispatch = {
        'host': host_to_object
    }
