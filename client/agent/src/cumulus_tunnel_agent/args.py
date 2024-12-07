import copy
import argparse

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




