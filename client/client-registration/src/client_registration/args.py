import argparse
import socket
import traceback
import os
import json
import copy
from pathlib import Path

from cumulus_tunnel_agent.state import StateManagementFunctions


DEFAULT_PORTS = "80,443"


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
        self.nat_check = True
        self.agent_name = socket.gethostname()
        self.tcp_ports = list()
        self.api_url = None
        self.api_headers = dict()
        self.api_config = dict()
        self.relay_id = 'default'

    def _set_config_from_data(self, data: dict):
        self.api_config = copy.deepcopy(data)
        self.api_url = copy.deepcopy(data['ApiUrl'])
        self.api_headers = copy.deepcopy(data['Headers'])
        self.api_headers['origin'] = 'agent'

    def load_api_configuration(self, config_file: str):
        with open(config_file, 'r') as f:
            data_json = f.read()
        data = json.loads(data_json)
        self._set_config_from_data(data=data)

    def load_api_configuration_from_cache(self, state_file_path: str):
        state_functions = StateManagementFunctions(state_file_path=state_file_path)
        previous_state_config = state_functions.get_state(state_key='state_config:{}'.format(args.relay_id))
        if previous_state_config is None:
            raise Exception('No prior state exists')
        if 'api_config' not in previous_state_config:
            raise Exception('Required API config not present in state data')
        self._set_config_from_data(data=previous_state_config['api_config'])

    def get_agent_key_name(self)->str:
        return 'agent-{}.json'.format(self.agent_name)
    
    def get_agent_extra_ip_addresses_key_name(self)->str:
        return 'agent-{}-extra-ip-addresses.json'.format(self.agent_name)


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
    '--identifier',
    help='I name for this agent (and system)',
    action='store',
    type=str,
    dest='agent_identifier',
    default='',
    required=False
)
parser.add_argument(
    '--ports',
    help='A string to override the default TCP ports to open. Comma separated list. Default: "80,443"',
    action='store',
    type=str,
    dest='ports',
    default=DEFAULT_PORTS,
    required=False
)
parser.add_argument(
    '--api-config',
    help='The path to the API configuration file (JSON format)',
    action='store',
    type=str,
    dest='api_config_file_path',
    default='{}{}.cumulus_tunnel_api.json'.format(Path.home(), os.sep),
    required=False
)
parser.add_argument(
    '--relay-id',
    help='The identifier of the relay server. If none is selected, the "default" server will be targeted. Firewall rules will be added to the security group for this server.',
    action='store',
    type=str,
    dest='relay_id',
    default='default',
    required=False
)
parser.add_argument(
    '--state-file',
    help='The full path to the state file to use. This will be a normal SQLite DB data file.',
    action='store',
    type=str,
    dest='state_file',
    default='{}{}.cumulus_tunnel_state.sqlite'.format(Path.home(), os.sep),
    required=False
)


args = parser.parse_args()


runtime_options.debug = args.verbose
runtime_options.update_interval_seconds = int(args.update_interval_seconds)

if os.path.exists(args.api_config_file_path) is False:
    runtime_options.load_api_configuration_from_cache(state_file_path=args.state_file)
else:
    runtime_options.load_api_configuration(config_file=args.api_config_file_path)

runtime_options.relay_id = '{}'.format(args.relay_id)

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
if len(args.agent_identifier) > 0:
    runtime_options.agent_name = '{}'.format(args.agent_identifier)

runtime_options.nat_check = not args.skip_nat_check


parsed_ports: str
parsed_ports = args.ports
for port in parsed_ports.split(','):
    if '-' not in port:
        try:
            port_as_int = int(port)
            if port_as_int > 0 and port_as_int <= 65535:
                port_as_str = '{}'.format(port_as_int)
                if port_as_str not in runtime_options.tcp_ports:
                    runtime_options.tcp_ports.append(port_as_str)
        except:
            traceback.print_exc()
    else:
        port_parts = port.split('-')
        if len(port_parts) == 2:
            try:
                start_port_as_int = int(port_parts[0])
                end_port_as_int = int(port_parts[1])
                for i in range(start_port_as_int, end_port_as_int+1):
                    port_as_str = '{}'.format(i)
                    if port_as_str not in runtime_options.tcp_ports:
                        runtime_options.tcp_ports.append(port_as_str)
            except:
                traceback.print_exc()




