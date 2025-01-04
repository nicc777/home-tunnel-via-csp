import argparse
import os
import socket
import json
from pathlib import Path


parser = argparse.ArgumentParser(
    prog='resource_server_tunnel',
    description='A script that will wrap around a SSH reverse tunnel while detaching from the console. The script can also be used to view potential active sessions and kill one of more of them.',
    epilog='*** Use at your own risk!   At least one of -n or -s or -c - if none of these are supplied, -s (status) will be the default option.'
)

parser.add_argument(
    '-v',
    '--verbose',
    help='Verbose mode - effectively running in debug mode. If you create a new tunnel, the log newly generated log file will also be put into debug mode.',
    action='store_true',
    default=False,
    required=False,
    dest='verbose'
)
parser.add_argument(
    '-n',
    '--new',
    help='Create a new reverse tunnel from the current machine.',
    action='store_true',
    default=False,
    required=False,
    dest='create_new_tunnel'
)
parser.add_argument(
    '--relay-name',
    help='The name of the relay server that was used to create it.',
    action='store',
    type=str,
    dest='relay_name',
    default='',
    required=True
)
parser.add_argument(
    '-d',
    '--detach',
    help='Only applicable when using the -n/--new parameter. Will detach from the console/terminal after the tunnel is established.',
    action='store_true',
    default=False,
    required=False,
    dest='detach_with_new_tunnel'
)
parser.add_argument(
    '-r',
    '--remote-port',
    help='The port number to listen on, on the relay server. MUST be supplied with the -n/--new parameter.',
    action='store',
    type=str,
    dest='remote_port',
    default='',
    required=False
)
parser.add_argument(
    '-l',
    '--local-port',
    help='The port number on the local machine to route traffic to. If NOT supplied with the -r/--remote-port option, the value will be assumed to be the same as the -r/--remote-port value',
    action='store',
    type=str,
    dest='local_port',
    default='',
    required=False
)
parser.add_argument(
    '--local-address',
    help='An optional IP address on the local system/network to forward to on the supplied local port. Default is 127.0.0.1 (localhost).',
    action='store',
    type=str,
    dest='local_address',
    default='127.0.0.1',
    required=False
)
parser.add_argument(
    '-s',
    '--status',
    help='Get the status of all known established tunnels. Cannot be used together with the -n/--new parameter.',
    action='store_true',
    default=False,
    required=False,
    dest='get_status'
)
parser.add_argument(
    '-c',
    '--close',
    help='Close a session. Supply a session ID as obtained from a previous run or from the -s/--status output. Cannot be used together with the -n/--new parameter.',
    action='store',
    type=str,
    dest='close_session_id',
    default='',
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
    '--cloud-profile-name',
    help='The name of the Cloud Provider Profile to use. The exact meaning may differ between various Cloud Service Providers. For AWS, this is the profile defined in the AWS CLI configuration files.',
    action='store',
    type=str,
    dest='cloud_profile_name',
    default='default',
    required=True
)
parser.add_argument(
    '--cloud-profile-region',
    help='The region name of the Cloud Provider Profile to use.Exact names may differ between Cloud Service Providers. The default value assumes the AWS region eu-central-1 is intended.',
    action='store',
    type=str,
    dest='cloud_profile_region',
    default='eu-central-1',
    required=True
)


args = parser.parse_args()

command = 'get_status'
if args.create_new_tunnel is True:
    command = 'create_new_tunnel'

if len(args.close_session_id) > 0:
    command = 'close_session_id'

if args.get_status is True and command == 'create_new_tunnel':
    raise Exception('You cannot supply both the -n and -s parameters at the same time')

if args.get_status is True and command == 'close_session_id':
    raise Exception('You cannot supply both the -s and -c parameters at the same time')

if args.create_new_tunnel is True and command == 'close_session_id':
    raise Exception('You cannot supply both the -n and -c parameters at the same time')

remote_port = None
local_port = None
if command == 'create_new_tunnel' and len(args.remote_port) == 0:
    raise Exception('The -r parameter is required to create a new tunnel')
else:
    remote_port = int(args.remote_port)
    if len(args.local_port) == 0:
        local_port = remote_port
    else:
        local_port = int(args.local_port)



