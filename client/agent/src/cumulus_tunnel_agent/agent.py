import os
import sys
import logging
import time
import json
import socket
import traceback
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
        if bucket_name.startswith('s://'):
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
        if bucket_name.startswith('s://'):
            bucket_name.replace('s3://', '')
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



def agent_main():
    logger.info('starting')
    do_loop = True
    while do_loop:
        logger.info('Main loop running')

        public_ip_addresses = get_public_ip_addresses()
        logger.info('public_ip_addresses: {}'.format(json.dumps(public_ip_addresses)))

        current_extra_ip_addresses_for_agent_at_destination = get_s3_file_as_dict(key=runtime_options.get_agent_extra_ip_addresses_key_name())
        logger.debug('agent_main(): current_extra_ip_addresses_for_agent_at_destination: {}'.format(json.dumps(current_extra_ip_addresses_for_agent_at_destination)))

        write_s3_data(
            key=runtime_options.get_agent_key_name(),
            data=public_ip_addresses
        )

        if len(runtime_options.extra_ip_addresses) > 0:
            write_s3_data(
                key=runtime_options.get_agent_extra_ip_addresses_key_name(),
                data=runtime_options.extra_ip_addresses
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
