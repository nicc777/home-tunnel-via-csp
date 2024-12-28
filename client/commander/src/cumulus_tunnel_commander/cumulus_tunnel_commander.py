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
import coloredlogs

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

SELECTED_LOG_LEVEL = logging.INFO
if DEBUG is True:
    SELECTED_LOG_LEVEL = logging.DEBUG

coloredlogs.install(SELECTED_LOG_LEVEL, fmt='%(asctime)s -  %(funcName)s:%(lineno)d - %(levelname)s - %(message)s')
logger = logging.getLogger('cumulus_tunnel_agent')

# Silence most of boto3 library logging
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

logger.debug('Running on host "{}" with default relay server name "{}"'.format(HOSTNAME, DEFAULT_TEMPLATE_TARGET_NAME))
logger.debug('configs: {}'.format(json.dumps(configs, default=str, indent=4)))


class RelayServer:

    def __init__(self, state_functions: StateManagementFunctions=StateManagementFunctions, configs: dict=dict()):
        self.configs = configs
        self.state_functions = state_functions
        if self.configs['purge_state_on_startup'] is True:
            self.configs.pop('purge_state_on_startup')
            self.state_functions.purger_state()
        previous_state_config = self.state_functions.get_state(state_key='state_config:{}'.format(args.agent_identifier))
        if previous_state_config is not None:
            logger.info('Using previously persisted state for agent identifier "{}"'.format(args.agent_identifier))
            self.configs = json.loads(previous_state_config)
            previous_state_config = None
        else:
            logger.info('Persisting configs for agent identifier "{}"'.format(args.agent_identifier))
            state_functions.write_state(state_key='state_config:{}'.format(args.agent_identifier), state_value=json.dumps(self.configs, default=str))

    def prepare_api_data(self)->dict:
        raise Exception('Must be implemented by the Cloud Provider specific implementation')

    def is_relay_server_created(self)->bool:
        raise Exception('Must be implemented by the Cloud Provider specific implementation')
    
    def create_relay_server(self, api_data:dict, timeout: int=1800):
        raise Exception('Must be implemented by the Cloud Provider specific implementation')
    
    def delete_relay_server_and_block_until_done(self, timeout: int=1800):
        raise Exception('Must be implemented by the Cloud Provider specific implementation')
    

class AwsRelayServer(RelayServer):

    def __init__(self, state_functions: StateManagementFunctions=StateManagementFunctions, configs: dict=dict()):
        super().__init__(configs=configs, state_functions=state_functions)
        import boto3
        import boto3.session
        self.session = boto3.session.Session(
            profile_name=self.configs['cloud_profile_name'],
            region_name=self.configs['cloud_profile_region']
        )

    def _get_current_cloud_formation_stack_names(self, next_token: str=None)->list:
        stack_names = list()
        client = self.session.client('cloudformation')
        response = dict()
        if next_token is not None:
            response = client.list_stacks(NextToken=next_token)
        else:
            response = client.list_stacks()
        if 'NextToken' in response:
            stack_names += self._list_cloudformation_stacks(next_token=response['NextToken'])
        if 'StackSummaries' in response:
            for stack_summary in response['StackSummaries']:
                if 'StackName' in stack_summary:
                    if 'DELETE' not in stack_summary['StackStatus']:
                        if stack_summary['StackName'] not in stack_names:
                            stack_names.append(stack_summary['StackName'])
                    else:
                        logger.warning(
                            'Previous version of stack named "{}" found, but ignored as it is in a "{}" state.'.format(
                                stack_summary['StackName'],
                                stack_summary['StackStatus']
                            )
                        )
        return stack_names

    def prepare_api_data(self)->dict:
        logger.info('Preparing API data')
        pass

    def is_relay_server_created(self)->bool:
        logger.info('Checking if the relay server has already been created.')
        current_cloudformation_stack_names = self._get_current_cloud_formation_stack_names()
        if 'cumulus-tunnel-api-resources-stack' not in current_cloudformation_stack_names:
            logger.error('It appears the Cumulus Tunnel API resources have not yet been created in this region: {}'.format(self.configs['cloud_profile_region']))
            raise Exception('It appears the Cumulus Tunnel API resources have not yet been created in this region: {}'.format(self.configs['cloud_profile_region']))
        if self.configs['relay_server_stack_name'] in current_cloudformation_stack_names:
            logger.info('  Stack "{}" has been created previously'.format(self.configs['relay_server_stack_name']))
            return True
        logger.info('  Stack "{}" has NOT been created'.format(self.configs['relay_server_stack_name']))
        return False
    
    def create_relay_server(self, api_data:dict, timeout: int=1800):
        logger.info('Creating relay server stack "{}"'.format(self.configs['relay_server_stack_name']))
        data = {
            'command': 'create_relay_server',
            'command_parameters': {
                'StackName': self.configs['relay_server_stack_name'],
                'StackParameters': api_data,
            },
        }
        pass

    def delete_relay_server_and_block_until_done(self, timeout: int=1800):
        logger.info('Deleting relay server stack "{}"'.format(self.configs['relay_server_stack_name']))
        data = {
            'command': 'delete_relay_server_stack',
            'command_parameters': {
                'StackName': self.configs['relay_server_stack_name'],
            },
        }
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
    relay_server = SUPPORTED_CLOUD_SERVICE_PROVIDERS[args.target_cloud_sp](
        state_functions=StateManagementFunctions(
            state_file_path=args.state_file,
            logger=logger
        ),
        configs=copy.deepcopy(configs)
    )

    if args.delete_relay_server is True:
        if relay_server.is_relay_server_created() is True:
            relay_server.delete_relay_server_and_block_until_done()
        else:
            logger.warning('Option --delete-relay-server provided, but relay server resources does not appear to exist.')

    do_loop = True
    if args.do_not_create_relay_server is True:
        do_loop = False
        logger.warning('The Relay Server Resources will NOT be deployed, and therefore the main loop will not start.')
    while do_loop:
        logger.info('Main loop running')

        if relay_server.is_relay_server_created() is False:
            relay_server.create_relay_server(
                api_data=relay_server.prepare_api_data()
            )
        
        if args.run_once is True:
            logger.info('Main loop DONE due to --run-once flag been true')
            do_loop = False
        else:
            logger.info('Main loop DONE - sleeping {} seconds'.format(args.update_interval_seconds))
            time.sleep(int(args.update_interval_seconds))


if __name__ == '__main__':
    agent_main()


logger.info('DONE')
