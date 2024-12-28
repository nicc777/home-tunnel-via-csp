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
    '--no-create-relay-server',
    help='Will not create the relay server resources if it does not exist. The --delete-relay-server parameter, if set, will be processed first. If you only want to delete the existing resources without re-creating it, set this flag.',
    action='store_true',
    default=False,
    required=False,
    dest='do_not_create_relay_server'
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
    '--state-file',
    help='The full path to the state file to use. This will be a normal SQLite DB data file.',
    action='store',
    type=str,
    dest='state_file',
    default='{}{}.cumulus_tunnel_state.sqlite'.format(Path.home(), os.sep),
    required=False
)
parser.add_argument(
    '--purge-state-on-startup',
    help='If this flag is set, the previous state will be deleted and the state from the various configuration options will be read fresh. Use this flag after any major update that could influence the state to be no longer valid. In theory you should be fine using this flag with every run.',
    action='store_true',
    default=False,
    required=False,
    dest='purge_state_on_startup'
)
parser.add_argument(
    '--cloud-profile-name',
    help='The name of the Cloud Provider Profile to use. The exact meaning may differ between various Cloud Service Providers. For AWS, this is the profile defined in the AWS CLI configuration files.',
    action='store',
    type=str,
    dest='cloud_profile_name',
    default='default',
    required=False
)
parser.add_argument(
    '--cloud-profile-region',
    help='The region name of the Cloud Provider Profile to use.Exact names may differ between Cloud Service Providers. The default value assumes the AWS region eu-central-1 is intended.',
    action='store',
    type=str,
    dest='cloud_profile_region',
    default='eu-central-1',
    required=False
)


args = parser.parse_args()


configs = dict()
with open(args.api_config_file_path, 'r') as f:
    configs['api_config'] = json.loads(f.read())
with open(args.param_config_file_path, 'r') as f:
    configs['param_config'] = json.loads(f.read())
configs['relay_server_stack_name'] = 'cumulus-tunnel-relay-server-{}-stack'.format(args.agent_identifier)
configs['cloud_profile_name'] = args.cloud_profile_name
configs['cloud_profile_region'] = args.cloud_profile_region
configs['purge_state_on_startup'] = args.purge_state_on_startup




