import argparse
import os
import socket
import json
from pathlib import Path


parser = argparse.ArgumentParser(
    prog='cumulus_tunnel_commander',
    description='Resource Server agent for cumulus-tunnel',
    epilog='Use at your own risk!'
)

parser.add_argument(
    '-v',
    '--verbose',
    action='store_true',
    default=False,
    required=False,
    dest='verbose'
)
parser.add_argument(
    '--cloud',
    help='A target cloud environment. Supported options: "aws"',
    action='store',
    type=str,
    dest='target_cloud_sp',
    default='aws',
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
    '--identifier',
    help='Name for this agent (and system)',
    action='store',
    type=str,
    dest='agent_identifier',
    default=socket.gethostname(),
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
    '--parameter-config',
    help='The path to the template parameter configuration file (JSON format) created during the build phase',
    action='store',
    type=str,
    dest='param_config_file_path',
    default='{}{}.cumulus_tunnel_standard_api_parameters.json'.format(Path.home(), os.sep),
    required=False
)


args = parser.parse_args()


configs = dict()
with open(args.api_config_file_path, 'r') as f:
    configs['api_config'] = json.loads(f.read())
with open(args.param_config_file_path, 'r') as f:
    configs['param_config'] = json.loads(f.read())



