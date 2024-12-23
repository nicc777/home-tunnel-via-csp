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
import boto3
import botocore

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
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


logger.info('DNS Updates every {} second with the client identifier set to  "{}"'.format(runtime_options.update_interval_seconds, runtime_options.agent_name))
logger.debug('Debug logging is enabled')

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


def get_s3_file_as_dict(key: str)->str:
    data = dict()
    try:
        bucket_name = runtime_options.destination
        if bucket_name.startswith('s3://'):
            bucket_name.replace('s3://', '')
        s3 = boto3.resource('s3')
        obj = s3.Object(bucket_name, key)
        raw = obj.get()['Body'].read().decode('utf-8')
        logger.debug('get_current_public_ip_address_file(): raw: {}'.format(raw))
        data = json.loads(raw)
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchKey':
            logger.error('Key "{}" does not exist'.format(key))
        else:
            logger.error('EXCEPTION: {}'.format(traceback.format_exc()))
    return data


def write_s3_data(key: str, data: dict):
    try:
        now = datetime.now()
        future_datetime = now + timedelta(hours=24)
        bucket_name = runtime_options.destination
        if bucket_name.startswith('s3://'):
            bucket_name.replace('s3://', '')
        logger.debug(
            'Wring to s3://{}/{} data: {}'.format(
                bucket_name,
                key,
                json.dumps(data)
            )
        )
        client = boto3.client('s3')
        response = client.put_object(
            Body=json.dumps(data).encode('utf-8'),
            Bucket=bucket_name,
            Expires=future_datetime,
            Key=key
        )
        logger.debug('write_s3_data(): Wrote key "{}" - response: {}'.format(key, json.dumps(response)))
    except:
        logger.error('EXCEPTION: {}'.format(traceback.format_exc()))


def delete_s3_key(key: str):
    try:
        bucket_name = runtime_options.destination
        if bucket_name.startswith('s://'):
            bucket_name.replace('s3://', '')
        client = boto3.client('s3')
        response = client.delete_object(
            Bucket=bucket_name,
            Key=key
        )
        logger.debug('delete_s3_key(): Deleted key "{}" - response: {}'.format(key, json.dumps(response)))
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchKey':
            logger.error('Key "{}" does not exist'.format(key))
        else:
            logger.error('EXCEPTION: {}'.format(traceback.format_exc()))


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


def agent_main():
    logger.info('starting')
    logger.info('API URL set to: {}'.format(runtime_options.api_url))
    logger.info('  Number of API headers set: {}'.format(len(runtime_options.api_headers)))
    do_loop = True
    while do_loop:
        logger.info('Main loop running')

        current_extra_ip_addresses_for_agent_at_destination = get_s3_file_as_dict(key=runtime_options.get_agent_extra_ip_addresses_key_name())
        logger.debug('agent_main(): current_extra_ip_addresses_for_agent_at_destination: {}'.format(json.dumps(current_extra_ip_addresses_for_agent_at_destination)))

        if runtime_options.nat_check is True:
            agent_data = add_ports_to_agent_data(agent_data=get_public_ip_addresses())
            logger.info('agent_data: {}'.format(json.dumps(agent_data)))

            write_s3_data(
                key=runtime_options.get_agent_key_name(),
                data=agent_data
            )

        if len(runtime_options.extra_ip_addresses) > 0:
            extra_agent_data = generate_extra_ip_address_data()
            if len(extra_agent_data) > 0:
                write_s3_data(
                    key=runtime_options.get_agent_extra_ip_addresses_key_name(),
                    data=extra_agent_data
                )
        else:
            if len(current_extra_ip_addresses_for_agent_at_destination) > 0:
                delete_s3_key(key=runtime_options.get_agent_extra_ip_addresses_key_name())

        if runtime_options.run_as_service is False:
            logger.info('Main loop DONE')
            do_loop = False
        else:
            logger.info('Main loop DONE - sleeping {} seconds'.format(runtime_options.update_interval_seconds))
            time.sleep(runtime_options.update_interval_seconds)


if __name__ == '__main__':
    agent_main()


logger.info('DONE')
