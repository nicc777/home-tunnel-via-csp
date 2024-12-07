import os
import sys
import logging
import time
import json
import socket
import requests

from cumulus_tunnel_agent.args import runtime_options

# import copy
import traceback
# import boto3


DEBUG = bool(int(os.getenv('DEBUG', '0')))
HOSTNAME = socket.gethostname()
DNS_UPDATE_INTERVAL_SECONDS = int(os.getenv('DNS_UPDATE_INTERVAL_SECONDS', '3600'))
PREFERRED_CLIENT_IDENTIFIER = os.getenv('PREFERRED_CLIENT_IDENTIFIER', runtime_options.agent_name)
DESTINATION = os.getenv('DESTINATION', '')


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


if runtime_options.agent_name == HOSTNAME:
    logger.debug('Checking if we can override the agent identifier...')
    if PREFERRED_CLIENT_IDENTIFIER != runtime_options.agent_name:
        runtime_options.agent_name = PREFERRED_CLIENT_IDENTIFIER


logger.info('DNS Updates every {} second with the client identifier set to  "{}"'.format(DNS_UPDATE_INTERVAL_SECONDS, runtime_options.agent_name))
logger.debug('Debug logging is enabled')

if runtime_options.destination == '' and len(DESTINATION) > 0:
    runtime_options.destination = DESTINATION

if len(runtime_options.extra_ip_addresses) > 0:
    for ip_address in runtime_options.extra_ip_addresses:
        logger.info('Adding extra IP address to firewall rule: {}'.format(ip_address))
else:
    logger.info('No extra IP addresses will be added')


if len(runtime_options.destination) == 0:
    raise Exception('The destination must have a value')
logger.info('Destination: {}'.format(runtime_options.destination))
logger.info('NAT check: {}'.format(runtime_options.nat_check))


def get_public_ipv4_address()->str:
    """
        curl 'https://api.ipify.org?format=json'
        {"ip":"86.81.190.151"}%   
    """
    ipv4_addr = ''
    try:
        url = 'https://api.ipify.org?format=json'
        logger.debug('get_public_ipv4_address(): Calling {}'.format(url))
        response = requests.get(url) 
        data = response.json()
        logger.debug('get_public_ipv4_address(): response: {}'.format(json.dumps(data)))
        if 'ip' in data:
            ipv4_addr = '{}/32'.format(data['ip'])
    except:
        traceback.print_exc()
    return ipv4_addr


def get_public_ipv6_address()->str:
    """
        curl 'https://api64.ipify.org?format=json'
        {"ip":"2a02:a466:bce4:0:7d4a:7a19:554a:42e2"}%  
    """
    ipv6_addr = ''
    try:
        url = 'https://api64.ipify.org?format=json'
        logger.debug('get_public_ipv6_address(): Calling {}'.format(url))
        response = requests.get(url) 
        data = response.json()
        logger.debug('get_public_ipv6_address(): response: {}'.format(json.dumps(data)))
        if 'ip' in data:
            ipv6_addr = '{}/128'.format(data['ip'])
    except:
        traceback.print_exc()
    return ipv6_addr


def get_public_ip_addresses()->dict:
    if runtime_options.nat_check is False:
        return dict()
    public_ip_addresses = dict()
    ipv4 = get_public_ipv4_address()
    ipv6 = get_public_ipv6_address()
    if len(ipv4) > 0:
        public_ip_addresses['ipv4'] = ipv4
    if len(ipv6) > 0:
        public_ip_addresses['ipv6'] = ipv6
    return public_ip_addresses


def get_current_public_ip_address_file()->str:
    data = dict()

    return data


def agent_main():
    logger.info('starting')
    do_loop = True
    while do_loop:
        logger.info('Main loop running')

        public_ip_addresses = get_public_ip_addresses()
        logger.info('public_ip_addresses: {}'.format(json.dumps(public_ip_addresses)))

        if runtime_options.run_as_service is False:
            logger.info('Main loop DONE')
            do_loop = False
        else:
            logger.info('Main loop DONE - sleeping {} seconds'.format(runtime_options.update_interval_seconds))
            time.sleep(runtime_options.update_interval_seconds)


if __name__ == '__main__':
    agent_main()


logger.info('DONE')
