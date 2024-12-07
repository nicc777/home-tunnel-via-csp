import argparse
import socket

parser = argparse.ArgumentParser(
    prog='cumulus_tunnel_agent',
    description='Agent for cumulus-tunnel',
    epilog='Use at your own risk!'
)

class RuntimeOptions:

    def __init__(self):
        self.exit_after_start = False
        self.debug = False
        self.update_interval_seconds = 86400
        self.extra_ip_addresses = list()
        self.run_as_service = True
        self.destination = ''
        self.nat_check = True
        self.agent_name = socket.gethostname()

    def get_agent_key_name(self)->str:
        return '{}.json'.format(self.agent_name)
    
    def get_agent_extra_ip_addresses_key_name(self)->str:
        return 'extra-ip-addresses-{}.json'.format(self.agent_name)


runtime_options = RuntimeOptions()

parser.add_argument(
    '-v',
    '--verbose',
    action='store_true',
    default=False,
    required=False
)
parser.add_argument(
    '--run-once',
    action='store_true',
    default=False,
    required=False,
    dest='run_once'
)
parser.add_argument(
    '--skip-nat-check',
    help='Skip the detection of this hosts NAT addresses (public IP addresses).',
    action='store_true',
    default=False,
    required=False,
    dest='skip_nat_check'
)
parser.add_argument(
    '--update-interval-seconds',
    help='How often the NAT address will be refreshed',
    action='store',
    dest='update_interval_seconds',
    default='3600',
    type=int,
    required=False
)
parser.add_argument(
    '--ips',
    help='Comma separated list of IP addresses',
    action='store',
    # default=list(),
    type=str,
    dest='ip_addresses',
    default='',
    required=False
)
parser.add_argument(
    '--dest',
    help='The destination. Only S3 is supported and therefore whatever value is set here will for now be assumed to be an S3 bucket',
    action='store',
    # default=list(),
    type=str,
    dest='destination',
    default='',
    required=False
)
parser.add_argument(
    '--identifier',
    help='I name for this agent (and system)',
    action='store',
    # default=list(),
    type=str,
    dest='agent_identifier',
    default='',
    required=False
)


args = parser.parse_args()

runtime_options.debug = args.verbose
runtime_options.update_interval_seconds = int(args.update_interval_seconds)
try:
    if len(args.ip_addresses) > 0:
        addresses = args.ip_addresses.split(',')
        addr: str
        for addr in addresses:
            runtime_options.extra_ip_addresses.append(addr.strip())
except:
    pass
if args.run_once is True:
    runtime_options.run_as_service = False
if len(args.destination) > 0:
    runtime_options.destination = '{}'.format(args.destination)
if len(args.agent_identifier) > 0:
    runtime_options.agent_name = '{}'.format(args.agent_identifier)

runtime_options.nat_check = not args.skip_nat_check



