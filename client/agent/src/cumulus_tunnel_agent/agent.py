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
from cumulus_tunnel_agent.args import runtime_options


DEBUG = bool(int(os.getenv('DEBUG', '0')))
HOSTNAME = socket.gethostname()


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
formatter = logging.Formatter('%(asctime)s - %(funcName)s:%(lineno)d - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


logger.info('DNS Updates every {} second with the client identifier set to  "{}"'.format(runtime_options.update_interval_seconds, runtime_options.agent_name))
logger.debug('Debug logging is enabled')

if len(runtime_options.extra_ip_addresses) > 0:
    for ip_address in runtime_options.extra_ip_addresses:
        logger.info('Adding extra IP address to firewall rule: {}'.format(ip_address))
else:
    logger.info('No extra IP addresses will be added')


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


def add_ports_to_agent_data(agent_data: dict)->dict:
    new_data = copy.deepcopy(agent_data)
    new_data['ports'] = dict()
    new_data['ports']['tcp'] = runtime_options.tcp_ports
    return new_data


def check_ip_address_is_ipv4_without_mask(input_address)->bool:
    try:
        c = ipaddress.ip_address(input_address)
        logger.debug('check_ip_address_is_ipv4_without_mask(): input_address={}   type: {}'.format(input_address, type(c)))
        return isinstance(c, ipaddress.IPv4Address)
    except:
        logger.debug('check_ip_address_is_ipv4_without_mask(): EXCEPTION: {}'.format(traceback.format_exc()))
        return False


def check_ip_address_is_ipv4_with_mask(input_address)->bool:
    try:
        c = ipaddress.ip_network(input_address)
        logger.debug('check_ip_address_is_ipv4_with_mask(): input_address={}   type: {}'.format(input_address, type(c)))
        return isinstance(c, ipaddress.IPv4Network)
    except:
        logger.debug('check_ip_address_is_ipv4_with_mask(): EXCEPTION: {}'.format(traceback.format_exc()))
        return False
    

def check_ip_address_is_ipv6_without_mask(input_address)->bool:
    try:
        c = ipaddress.ip_address(input_address)
        logger.debug('check_ip_address_is_ipv6_without_mask(): input_address={}   type: {}'.format(input_address, type(c)))
        return isinstance(c, ipaddress.IPv6Address)
    except:
        logger.debug('check_ip_address_is_ipv6_without_mask(): EXCEPTION: {}'.format(traceback.format_exc()))
        return False


def check_ip_address_is_ipv6_with_mask(input_address)->bool:
    try:
        c = ipaddress.ip_network(input_address)
        logger.debug('check_ip_address_is_ipv6_with_mask(): input_address={}   type: {}'.format(input_address, type(c)))
        return isinstance(c, ipaddress.IPv6Network)
    except:
        logger.debug('check_ip_address_is_ipv6_with_mask(): EXCEPTION: {}'.format(traceback.format_exc()))
        return False


def validate_and_return_ip_address(input_address: str, add_mask: bool=True, mask_value_ipv4: str='/32', mask_value_ipv6: str='/128')->str:
    input_address = input_address.replace('"', '')
    if check_ip_address_is_ipv4_without_mask(input_address=input_address) is True:
        if add_mask is True:
            return '{}{}'.format(input_address, mask_value_ipv4)
        else:
            return input_address
    if check_ip_address_is_ipv4_with_mask(input_address=input_address) is True:
        if add_mask is True:
            return input_address
        else:
            parts = input_address.split('/')
            return parts[0]
    if check_ip_address_is_ipv6_without_mask(input_address=input_address) is True:
        if add_mask is True:
            return '{}{}'.format(input_address, mask_value_ipv6)
        else:
            return input_address
    if check_ip_address_is_ipv6_with_mask(input_address=input_address) is True:
        if add_mask is True:
            return input_address
        else:
            parts = input_address.split('/')
            return parts[0]
    raise Exception('Invalid IP Address: {}'.format(input_address))
    

def detect_ip_address_type_and_return_str(input_address: str)->str:
    input_address = input_address.replace('"', '')
    if check_ip_address_is_ipv4_without_mask(input_address=input_address) is True:
        return 'ipv4'
    if check_ip_address_is_ipv4_with_mask(input_address=input_address) is True:
        return 'ipv4'
    if check_ip_address_is_ipv6_without_mask(input_address=input_address) is True:
        return 'ipv6'
    if check_ip_address_is_ipv6_with_mask(input_address=input_address) is True:
        return 'ipv6'
    raise Exception('Not a valid IP address: {}'.format(input_address))


def generate_extra_ip_address_data()->dict:
    extra_ip_addresses = dict()
    extra_ip_addresses['addresses'] = dict()
    extra_ip_addresses['addresses']['ipv4'] = list()
    extra_ip_addresses['addresses']['ipv6'] = list()
    for ip_address_candidate in runtime_options.extra_ip_addresses:
        try:
            final_ip_address_with_mask = validate_and_return_ip_address(input_address=ip_address_candidate)
            ip_adr_type = detect_ip_address_type_and_return_str(input_address=final_ip_address_with_mask)
            extra_ip_addresses['addresses'][ip_adr_type].append(final_ip_address_with_mask)
        except:
            logger.error('EXCEPTION: {}'.format(traceback.format_exc()))
            logger.error('Failed to evaluate and consider IP address "{}" - ignored'.format(ip_address_candidate))
    if len(extra_ip_addresses['addresses']['ipv4']) == 0 and len(extra_ip_addresses['addresses']['ipv6']) == 0:
        return dict()
    extra_ip_addresses['ports'] = dict()
    extra_ip_addresses['ports']['tcp'] = runtime_options.tcp_ports
    return extra_ip_addresses


def collect_all_data(agent_id: str, relay_id: str)->dict:
    collected_data = dict()
    collected_data['NatAddressData'] = dict()
    collected_data['ExtraIpAddressData'] = dict()
    collected_data['AgentId'] = agent_id
    collected_data['RelayId'] = relay_id
    if runtime_options.nat_check is True:
        agent_data = add_ports_to_agent_data(agent_data=get_public_ip_addresses())
        logger.info('agent_data: {}'.format(json.dumps(agent_data)))
        collected_data['NatAddressData'] = copy.deepcopy(agent_data)
    if len(runtime_options.extra_ip_addresses) > 0:
        extra_agent_data = generate_extra_ip_address_data()
        logger.info('extra_agent_data: {}'.format(json.dumps(extra_agent_data)))
        collected_data['ExtraIpAddressData'] = copy.deepcopy(extra_agent_data)
    logger.debug('collected_data: \n{}\n\n'.format(json.dumps(collected_data, default=str, indent=4)))
    return collected_data


def post_data(url: str, data:dict, extra_headers: dict):
    response = requests.post(
        url=url,
        data=json.dumps(data),
        headers=extra_headers
    )
    logger.debug('POST: url: {}'.format(url))
    logger.debug('POST: data: \n{}\n\n'.format(json.dumps(data, default=str, indent=4)))
    logger.debug('POST: extra_headers: \n{}\n\n'.format(json.dumps(extra_headers, default=str, indent=4)))
    status_code = response.status_code
    response_text = response.text
    json_response = None
    if response_text: # check if the response is not empty
        try:
            json_response = response.json()
        except json.JSONDecodeError:
            logger.error('Warning: Could not decode JSON response: {}'.format(response_text))
    return int(status_code), json_response, response_text


def agent_main():
    logger.info('starting')
    logger.info('API URL set to: {}'.format(runtime_options.api_url))
    logger.info('  Number of API headers set: {}'.format(len(runtime_options.api_headers)))
    do_loop = True
    while do_loop:
        logger.info('Main loop running')

        collected_agent_data = collect_all_data(agent_id=runtime_options.agent_name, relay_id=runtime_options.relay_id)
        logger.debug('API Configuration: \n{}\n\n'.format(json.dumps(runtime_options.api_config, default=str, indent=4)))
        status_code, json_response, response_text = post_data(
            url=runtime_options.api_url,
            data=collected_agent_data,
            extra_headers=runtime_options.api_headers
        )
        logger.info('Submitted data. Return code: {}'.format(status_code))
        logger.debug('Return message raw: {}'.format(response_text))
        if json_response is not None:
            logger.debug('Return JSON: {}'.format(json.dumps(json_response, default=str)))
        
        if runtime_options.run_as_service is False:
            logger.info('Main loop DONE')
            do_loop = False
        else:
            logger.info('Main loop DONE - sleeping {} seconds'.format(runtime_options.update_interval_seconds))
            time.sleep(runtime_options.update_interval_seconds)


if __name__ == '__main__':
    agent_main()


logger.info('DONE')
