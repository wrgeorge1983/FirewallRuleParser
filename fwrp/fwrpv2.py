"""
fwrpv2.py
module for manipulating and understanding firewall rulesets
"""
import attr

@attr.s
class ACLNode(object):
	name = attr.ib()
	

@attr.s
class ACLObject(ACLNode):
	pass

@attr.s
class ACLGroup(ACLObject):
	"""
	Only use this if we have to
	"""
	pass
