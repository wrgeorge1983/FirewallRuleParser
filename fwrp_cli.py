import click

from fwrp import firewallruleparser
from fwrp import fwrpv2

@click.command()
def cli():
	node = fwrpv2.ACLGroup(name='x')
	print(node)


if __name__ == '__main__':
	cli()