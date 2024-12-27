import os
import sys
import logging
import time
import json
import socket
import traceback
import copy
import ipaddress
from datetime import datetime, timedelta

import requests

from cumulus_tunnel_commander.args import args, configs
from cumulus_tunnel_commander.state import StateManagementFunctions

DEFAULT_TEMPLATE_TARGET_NAME_POSTFIX_MAPPING_PER_CLOUD_SP = {
    'aws': '-stack' # For AWS the DEFAULT_TEMPLATE_TARGET_NAME will be a CloudFormation stack name
}
DEBUG = bool(int(os.getenv('DEBUG', '0')))
HOSTNAME = socket.gethostname()
DEFAULT_TEMPLATE_TARGET_NAME = '{}{}'.format(
    HOSTNAME,
    DEFAULT_TEMPLATE_TARGET_NAME_POSTFIX_MAPPING_PER_CLOUD_SP[args.target_cloud_sp]
)


if args.verbose is True:
    DEBUG = True

logger = logging.getLogger('cumulus_tunnel_agent')
logger.setLevel(logging.INFO)
if DEBUG is True:
    logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
if DEBUG is True:
    ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(funcName)s:%(lineno)d - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

logger.debug('Running on host "{}" with default relay server name "{}"'.format(HOSTNAME, DEFAULT_TEMPLATE_TARGET_NAME))
logger.debug('configs: {}'.format(json.dumps(configs, default=str, indent=4)))

state = StateManagementFunctions(state_file_path=args.state_file, logger=logger)


class RelayServer:

    def __init__(self):
        self.state = state

    def prepare_api_data(self)->dict:
        raise Exception('Must be implemented by the Cloud Provider specific implementation')

    def is_relay_server_created(self)->bool:
        raise Exception('Must be implemented by the Cloud Provider specific implementation')
    
    def create_relay_server(self, api_data:dict):
        raise Exception('Must be implemented by the Cloud Provider specific implementation')
    
    def delete_relay_server_and_block_until_done(self, timeout: int=1800):
        raise Exception('Must be implemented by the Cloud Provider specific implementation')
    

class AwsRelayServer(RelayServer):

    def __init__(self):
        super().__init__()

    def prepare_api_data(self)->dict:
        logger.info('Preparing API data')
        pass

    def is_relay_server_created(self)->bool:
        logger.info('Checking if the relay server has already been created.')
        return False
    
    def create_relay_server(self, api_data:dict):
        logger.info('Creating relay server with ID "{}"'.format(args.agent_identifier))
        pass

    def delete_relay_server_and_block_until_done(self, timeout: int=1800):
        logger.info('Deleting relay server with ID "{}"'.format(args.agent_identifier))
        pass


SUPPORTED_CLOUD_SERVICE_PROVIDERS = {
    'aws': AwsRelayServer
}


def agent_main():
    logger.info('starting')
    logger.info('API URL set to: {}'.format(configs['api_config']['ApiUrl']))
    logger.info('  Number of API headers set: {}'.format(len(configs['api_config']['Headers'])))

    if args.enable_http_proxy is True:
        if args.http_proxy_domain_record_name == 'not-set' or len(args.http_proxy_domain_record_name) == 0:
            logger.error('When the --enable-http-proxy flag is set, the --http-proxy-record-name parameter MUST be supplied and can not have a empty value or the value "not-set"')
            raise Exception('When the --enable-http-proxy flag is set, the --http-proxy-record-name parameter MUST be supplied and can not have a empty value or the value "not-set"')

    if args.target_cloud_sp not in SUPPORTED_CLOUD_SERVICE_PROVIDERS:
        logger.error('Requested Cloud provider "{}" is not yet supported.'.format(args.target_cloud_sp))
        raise Exception('Requested Cloud provider "{}" is not yet supported.'.format(args.target_cloud_sp))

    relay_server: RelayServer
    relay_server = SUPPORTED_CLOUD_SERVICE_PROVIDERS[args.target_cloud_sp]()

    if args.delete_relay_server is True:
        if relay_server.is_relay_server_created() is True:
            relay_server.delete_relay_server_and_block_until_done()
        else:
            logger.warning('Option --delete-relay-server provided, but relay server resources does not appear to exist.')

    do_loop = True
    while do_loop:
        logger.info('Main loop running')

        if relay_server.is_relay_server_created() is False:
            relay_server.create_relay_server(
                api_data=relay_server.prepare_api_data()
            )
        
        if args.run_once is True:
            logger.info('Main loop DONE due to run_once flag been true')
            do_loop = False
        else:
            logger.info('Main loop DONE - sleeping {} seconds'.format(args.update_interval_seconds))
            time.sleep(int(args.update_interval_seconds))


if __name__ == '__main__':
    agent_main()


logger.info('DONE')
