import argparse

from tunnel_server_local_relay import logger


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
    '--resource-client-port',
    help='The TCP port that the resource server will connect to',
    action='store',
    type=str,
    dest='resource_client_port',
    required=True
)
parser.add_argument(
    '--remote-client-port',
    help='The TCP port that the resource server will connect to',
    action='store',
    type=str,
    dest='remote_client_port',
    required=True
)

args = parser.parse_args()

logger.info('resource_client_port : {}'.format(args.resource_client_port))
logger.info('remote_client_port   : {}'.format(args.remote_client_port))

