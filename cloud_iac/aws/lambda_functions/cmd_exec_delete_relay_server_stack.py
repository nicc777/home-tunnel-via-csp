import logging
import os
import sys
import json
import traceback
import boto3


DEBUG = bool(int(os.getenv('DEBUG', '0')))


logger = logging.getLogger(os.path.basename(__file__).replace('.py', ''))
logger.setLevel(logging.INFO)
if DEBUG is True:
    logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
if DEBUG is True:
    ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(funcName)s:%(lineno)d -  %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# Silence most of boto3 library logging
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

# Prevent duplicate log entries
logger.propagate = False

def get_deployed_cloudformation_stack_names(next_token: str=None)->list:
    stack_names = list()
    client = boto3.client('cloudformation')
    response = dict()
    if next_token is not None:
        response = client.list_stacks(NextToken=next_token)
    else:
        response = client.list_stacks()
    if 'NextToken' in response:
        stack_names += get_deployed_cloudformation_stack_names(next_token=response['NextToken'])
    if 'StackSummaries' in response:
        for stack_summary in response['StackSummaries']:
            if 'StackName' in stack_summary:
                if 'DELETE' not in stack_summary['StackStatus']:
                    if stack_summary['StackName'] not in stack_names:
                        stack_names.append(stack_summary['StackName'])
                else:
                    logger.info(
                        'Previous version of stack named "{}" found, but ignored as it is in a "{}" state.'.format(
                            stack_summary['StackName'],
                            stack_summary['StackStatus']
                        )
                    )
    logger.debug('stack_names: {}'.format(stack_names))
    return stack_names


def extract_body_as_dict_from_event_record(record)->dict:
    try:
        return json.loads(record['body'])
    except:
        logger.error('Failed to get body from event: {}'.format(record))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    return dict()


def extract_stack_name(record: dict)->str:
    stack_name = None
    try:
        if record['command'] == 'delete_relay_server_stack':
            command_parameters = record['command_parameters']
            if isinstance(command_parameters, str):
                command_parameters = json.loads(record['command_parameters'])
            logger.debug('command_parameters: {}'.format(json.dumps(command_parameters, default=str)))
            if 'parameter_name' not in command_parameters or 'parameter_value' not in command_parameters:
                logger.error('Expected keys in command parameters not found: {}'.format(record['command_parameters']))
            else:
                if command_parameters['parameter_name'] == 'stack_name':
                    stack_name = command_parameters['parameter_value']
        else:
            logger.error('Only supported command: "delete_relay_server_stack" - got "{}"'.format(record['command']))
    except:
        logger.error('Failed to get stack name from event: {}'.format(record))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    if stack_name is None:
        logger.error('Unable to determine stack name to delete. No action will be taken.')
    return stack_name


def delete_stack(stack_name: str):
    try:
        client = boto3.client('cloudformation')
        client.delete_stack(StackName=stack_name)
    except Exception as e:
        logger.error('{}'.format(str(e)))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))


def handler(event, context):
    logger.debug('event: {}'.format(json.dumps(event, default=str)))
    stack_name = None
    current_stacks = get_deployed_cloudformation_stack_names()
    logger.debug('Current CloudFormation stacks: {}'.format(current_stacks))
    if 'Records' in event:
        for record in event['Records']:
            command_data = extract_body_as_dict_from_event_record(record=record)
            logger.debug('command_data: {}'.format(json.dumps(command_data, default=str)))
            stack_name = extract_stack_name(record=command_data)
    elif 'command' in event and 'command_parameters' in event:
        if event['command'] == 'delete_relay_server_stack':
            stack_name = extract_stack_name(record=event)
    if stack_name is not None:
        if stack_name in current_stacks:
            logger.info('Deleting stack named "{}"'.format(stack_name))
            delete_stack(stack_name=stack_name)
        else:
            logger.warning('It looks like stack "{}" is not in the current deployed stacks - no action will be taken. Current stacks: {}'.format(stack_name, current_stacks))
    return "ok"

