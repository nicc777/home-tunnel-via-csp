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


def format_response(status_code: int=200, body: dict=dict()):
    return {
        "isBase64Encoded": False,
        "statusCode": status_code,
        "headers": {},
        "multiValueHeaders": {},
        "body": json.dumps(body, default=str)
    }


def get_command_body(event)->dict:
    if 'body' not in event:
        logger.error('Invalid event data. Expected key "body" not found')
        raise Exception('Invalid event data. Expected key "body" not found')
    return json.loads(event['body'])


def get_stack_status(stack_name: str, next_token: str=None):
    try:
        client = boto3.client('cloudformation')
        response = dict()
        if next_token is not None:
            response = client.describe_stacks(StackName=stack_name,NextToken=next_token)
        else:
            response = client.describe_stacks(StackName=stack_name)
        logger.debug('response: {}'.format(json.dumps(response, default=str)))
        status = 'UNKNOWN'
        status_reason = 'n/a'
        if 'NextToken' in response:
            logger.warning('Ignoring NextToken for now...')
        if 'Stacks' in response:
            for stack in response['Stacks']:
                if 'StackName' in stack:
                    if stack['StackName'] == stack_name:
                        if 'StackStatus' in stack:
                            logger.info('\t StackStatus       : {}'.format(stack['StackStatus']))
                            status = stack['StackStatus']
                        else:
                            logger.warning('Did NOT find "StackStatus" field in stack: {}'.format(json.dumps(stack, default=str)))
                        if 'StackStatusReason' in stack:
                            logger.info('\t StackStatusReason : {}'.format(stack['StackStatusReason']))
                            status_reason = stack['StackStatusReason']
                    else:
                        logger.warning('Ignoring stack named "{}"...'.format(stack['StackName']))
                else:
                    logger.warning('Expected the field "StackName" in stack: {}'.format(stack))
        else:
            logger.error('Unrecognized response: {}'.format(response))
        return status, status_reason
    except:
        logger.error('Failed to get stack status for stack "{}"'.format(stack_name))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))


def handler(event, context):
    logger.debug('event: {}'.format(json.dumps(event, default=str)))
    command_body = get_command_body(event=event)

    """
    {
        'command': 'get_stack_status',
        'command_parameters': {
            'StackName': self.configs['relay_server_stack_name'],
        },
    }
    """
    if 'command' in command_body:
        if command_body['command'] == 'get_stack_status':
            stack_name = None
            if 'command_parameters' in command_body:
                if 'StackName' in command_body['command_parameters']:
                    stack_name = command_body['command_parameters']['StackName']
            if stack_name is not None:
                status, status_reason = get_stack_status(stack_name=stack_name)
                return format_response(
                    status_code=200,
                    body={
                        'stack_name': stack_name,
                        'stack_status': status,
                        'stack_status_reason': status_reason,
                    }
                )

    return format_response(status_code=599, body={'error': 'Command Instruction Failed'})

