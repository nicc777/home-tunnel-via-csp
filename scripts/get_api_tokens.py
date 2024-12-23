import logging
import os
import sys
import json
import copy
import boto3
import tempfile
import base64


DEBUG = bool(int(os.getenv('DEBUG', '0')))
AWS_PROFILE = os.getenv('AWS_PROFILE', 'default')
AWS_REGION = os.getenv('AWS_REGION', 'eu-central-1')


boto3_session = boto3.session.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)


logger = logging.getLogger('cumulus_tunnel_build_and_deploy')
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


def get_stack_identifiers(name: str='cumulus-tunnel-event-resources', next_token: str=None)->list:
    stack_identifiers = list()
    client = boto3_session.client('cloudformation')
    response = dict()
    if next_token is not None:
        response = client.list_stacks(NextToken=next_token)
    else:
        response = client.list_stacks()
    if 'NextToken' in response:
        stack_identifiers += get_stack_identifiers(name=name, next_token=response['NextToken'])
    if 'StackSummaries' in response:
        for data in response['StackSummaries']:
            if name in data['StackName']:
                record = dict()
                record['StackId'] = data['StackId']
                record['StackName'] = data['StackName']
                record['StackStatus'] = data['StackStatus']
                record['CreationTime'] = data['CreationTime']
                # logger.debug('INTERIM data: {}'.format(json.dumps(record, default=str)))
                stack_identifiers.append(record)
    logger.info('Retrieved {} stacks'.format(len(stack_identifiers)))
    return stack_identifiers


def parse_and_get_most_recent_stack(stack_identifiers: list)->dict:
    current_stack_identifier_record = dict()
    for stack in stack_identifiers:
        if len(current_stack_identifier_record) == 0:
            current_stack_identifier_record = copy.deepcopy(stack)
        else:
            if stack['CreationTime'] > current_stack_identifier_record['CreationTime']:
                current_stack_identifier_record = copy.deepcopy(stack)
    return current_stack_identifier_record


def get_cloudformation_resources(stack_name: str, next_token: str=None)->list:
    resources = list()
    client = boto3_session.client('cloudformation')
    response = dict()
    if next_token is not None:
        response = client.list_stack_resources(StackName=stack_name, NextToken=next_token)
    else:
        response = client.list_stack_resources(StackName=stack_name)
    if 'NextToken' in response:
        resources += get_cloudformation_resources(stack_name=stack_name, next_token=response['NextToken'])
    if 'StackResourceSummaries' in response:
        for data in response['StackResourceSummaries']:
            record = dict()
            record['LogicalResourceId'] = data['LogicalResourceId']
            record['PhysicalResourceId'] = data['PhysicalResourceId']
            record['ResourceStatus'] = data['ResourceStatus']
            resources.append(record)
    return resources


def get_resource_physical_id(logical_id: str, resources: list)->tuple:
    for record in resources:
        if record['LogicalResourceId'] == logical_id:
            return record['PhysicalResourceId'], record['ResourceStatus']


def get_api_token(api_key_id: str):
    client = boto3_session.client('apigateway')
    response = client.get_api_key(
        apiKey=api_key_id,
        includeValue=True
    )
    return response['value']


def get_secret_value(secret_id: str)->str:
    client = boto3_session.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_id)
    return response['SecretString']


def get_exports(next_token:str=None)->list:
    exports = list()
    client = boto3_session.client('cloudformation')
    response = dict()
    if next_token is not None:
        response = client.list_exports(NextToken=next_token)
    else:
        response = client.list_exports()
    if 'NextToken' in response:
        exports += get_exports(next_token=response['NextToken'])
    if 'Exports' in response:
        for export in response['Exports']:
            exports.append(
                {
                    export['Name']: export['Value']
                }
            )
    return exports


def get_api_gw_url(exports: list)->str:
    url = None
    for record in exports:
        for name, value in record.items():
            if name == 'CumulusTunnelApiUrl':
                url = '{}'.format(value)
    return url


def main():
    stack_identifiers = get_stack_identifiers()
    most_recent_stack = parse_and_get_most_recent_stack(stack_identifiers=stack_identifiers)
    logger.debug('most_recent_stack: {}'.format(json.dumps(most_recent_stack, default=str)))
    resources = get_cloudformation_resources(stack_name=most_recent_stack['StackName'])
    logger.debug('resources: {}'.format(json.dumps(resources, default=str)))
    api_key_logical_id, api_key_resource_status = get_resource_physical_id(
        logical_id='ApiKey', 
        resources=resources
    )
    logger.debug('API Key "{}" has status "{}"'.format(api_key_logical_id, api_key_resource_status))
    api_gateway_stage_token = get_api_token(api_key_id=api_key_logical_id)
    logger.info('HEADER: x-api-key: {}'.format(api_gateway_stage_token))
    secrets_manager_logical_id, secrets_manager_resource_status = get_resource_physical_id(
        logical_id='CumulusTunnelAuthTokenSecret', 
        resources=resources
    )
    logger.debug('SecretsManager "{}" has status "{}"'.format(secrets_manager_logical_id, secrets_manager_resource_status))
    secret_value = get_secret_value(secret_id=secrets_manager_logical_id)
    logger.debug('secret_value: {}'.format(secret_value))
    secret_data = json.loads(secret_value)
    authorizer_string = '{}:{}'.format(secret_data['username'], secret_data['password'])
    base64_string = base64.b64encode(authorizer_string.encode('utf-8')).decode('utf-8')
    logger.info('HEADER x-cumulus-tunnel-credentials: {}'.format(base64_string))
    exports = get_exports()
    logger.debug('exports: {}'.format(json.dumps(exports)))
    api_url = get_api_gw_url(exports=exports)
    logger.info('URL: {}'.format(api_url))
    test_payload = {
        'echo': 'test',
    }
    test_url = 'curl -X POST -d \'{}\' --header "x-api-key: {}" --header "x-cumulus-tunnel-credentials: {}" --header "origin: agent" {}'.format(
        json.dumps(test_payload, default=str),
        api_gateway_stage_token,
        base64_string,
        api_url
    )
    logger.info('TEST URL: {}'.format(test_url))

    temp_dir = tempfile.gettempdir()
    config_file = '{}{}cumulus_tunnel_api.json'.format(temp_dir, os.sep)
    config_data = {
        'ApiUrl': api_url,
        'Headers': {
            'x-api-key': api_gateway_stage_token,
            'x-cumulus-tunnel-credentials': base64_string,
        },
    }
    with open(config_file, 'w') as f:
        f.write('{}'.format(json.dumps(config_data)))

    logger.info('CONFIG FILE written to "{}"'.format(config_file))
    logger.info('Copy the config file to the resource server(s) and agent(s)')


if __name__ == '__main__':
    main()

