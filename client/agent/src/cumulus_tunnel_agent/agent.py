import os
import sys
import logging
import socket
import time
from cumulus_tunnel_agent.args import runtime_options
# import copy
# import requests
# import json
# import traceback
# import boto3


DEBUG = bool(int(os.getenv('DEBUG', '0')))
HOSTNAME = socket.gethostname()
DNS_UPDATE_INTERVAL_SECONDS = int(os.getenv('DNS_UPDATE_INTERVAL_SECONDS', '3600'))
PREFERRED_CLIENT_IDENTIFIER = os.getenv('PREFERRED_CLIENT_IDENTIFIER', HOSTNAME)


if runtime_options.debug is True:
    DEBUG = True

logger = logging.getLogger('cumulus_tunnel_agent')
logger.setLevel(logging.INFO)
if DEBUG is True:
    logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
if DEBUG is True:
    ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


if DNS_UPDATE_INTERVAL_SECONDS != 3600:
    if runtime_options.update_interval_seconds == 3600:
        runtime_options.update_interval_seconds = DNS_UPDATE_INTERVAL_SECONDS


logger.info('DNS Updates every {} second with the client identifier set to  "{}"'.format(DNS_UPDATE_INTERVAL_SECONDS, PREFERRED_CLIENT_IDENTIFIER))
logger.debug('Debug logging is enabled')

if len(runtime_options.extra_ip_addresses) > 0:
    for ip_address in runtime_options.extra_ip_addresses:
        logger.info('Adding extra IP address to firewall rule: {}'.format(ip_address))
else:
    logger.info('Only the detected public IP address will be added')


if len(runtime_options.destination) == 0:
    raise Exception('The destination must have a value')
logger.info('Destination: {}'.format(runtime_options.destination))


def agent_main():
    logger.info('starting')
    do_loop = True
    while do_loop:
        logger.info('Main loop running')

        if runtime_options.run_as_service is False:
            logger.info('Main loop DONE')
            do_loop = False
        else:
            logger.info('Main loop DONE - sleeping {} seconds'.format(runtime_options.update_interval_seconds))
            time.sleep(runtime_options.update_interval_seconds)


if __name__ == '__main__':
    agent_main()


logger.info('DONE')
