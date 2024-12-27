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
    '--enable-http-proxy',
    help='If supplied, will enable the HTTP reverse proxy on the relay server. This will automatically create a Load Balancer to the web ports of the relay server, where Nginx will run with a reverse proxy to the forwarded port 8080 (hard coded for now). WHen this setting is enabled, the --http-proxy-record-name parameter must also be set.',
    action='store_true',
    default=False,
    required=False,
    dest='enable_http_proxy'
)
parser.add_argument(
    '--http-proxy-record-name',
    help='DNS record name that will be bound to the Load Balancer that will forward traffic to the relay server.',
    action='store',
    type=str,
    required=False,
    dest='http_proxy_domain_record_name',
    default='not-set'
)
parser.add_argument(
    '--delete-relay-server',
    help='If set, this will first delete any existing relay server, if it exists. Typically you would run this with the --run-once, for a once off action. If run in loop-mode (default), any existing relay server resources will only be deleted on startup, before a new relay server will be created.',
    action='store_true',
    default=False,
    required=False,
    dest='delete_relay_server'
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
    help='Name for this agent (and system). This value will also be used as the ID of the relay server, and must therefore be a valid DNS host name (without the domain name portion).',
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
parser.add_argument(
    '-state-file',
    help='The full path to the state file to use. This will be a normal SQLite DB data file.',
    action='store',
    type=str,
    dest='state_file',
    default='{}{}.cumulus_tunnel_state.sqlite'.format(Path.home(), os.sep),
    required=False
)


args = parser.parse_args()


configs = dict()
with open(args.api_config_file_path, 'r') as f:
    configs['api_config'] = json.loads(f.read())
with open(args.param_config_file_path, 'r') as f:
    configs['param_config'] = json.loads(f.read())



