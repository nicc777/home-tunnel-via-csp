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


class RelayServer:

    def __init__(self):
        pass

    def create_command_api_data(self)->dict:
        raise Exception('Must be implemented by the Cloud Provider specific implementation')
    

class AwsRelayServer(RelayServer):

    def __init__(self):
        super().__init__()

    def create_command_api_data(self)->dict:
        pass



def agent_main():
    logger.info('starting')
    logger.info('API URL set to: {}'.format(configs['api_config']['ApiUrl']))
    logger.info('  Number of API headers set: {}'.format(len(configs['api_config']['Headers'])))
    do_loop = True
    while do_loop:
        logger.info('Main loop running')

        
        if args.run_once is True:
            logger.info('Main loop DONE due to run_once flag been true')
            do_loop = False
        else:
            logger.info('Main loop DONE - sleeping {} seconds'.format(args.update_interval_seconds))
            time.sleep(int(args.update_interval_seconds))


if __name__ == '__main__':
    agent_main()


logger.info('DONE')
