import logging
import os
import sys
import json
import copy
import boto3
import traceback


DEBUG = bool(int(os.getenv('DEBUG', '0')))


logger = logging.getLogger(os.path.basename(__file__).replace('.py', ''))
for handler in logger.handlers[:]: 
    logger.removeHandler(handler)
logger.setLevel(logging.INFO)
if DEBUG is True:
    logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
if DEBUG is True:
    ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')
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

def get_command_agent_context(event)->str:
    if 'headers' not in event:
        logger.error('Invalid event data. Expected key "headers" not found')
        raise Exception('Invalid event data. Expected key "headers" not found')
    headers = event['headers']
    if 'origin' not in headers:
        logger.error('Expected header "origin" not found')
        raise Exception('Expected header "origin" not found')
    return '{}'.format(headers['origin'])


def get_command_body(event)->dict:
    if 'body' not in event:
        logger.error('Invalid event data. Expected key "body" not found')
        raise Exception('Invalid event data. Expected key "body" not found')
    return json.loads(event['body'])


def validate_agent_command(command_body: dict):
    logger.debug('Validating AGENT command: {}'.format(json.dumps(command_body, default=str)))
    return


def validate_resource_server_command(command_body: dict):
    logger.debug('Validating RESOURCE SERVER command: {}'.format(json.dumps(command_body, default=str)))
    return


def parse_event(event):
    client_context = get_command_agent_context(event=event)
    command_body = get_command_body(event=event)
    
    if client_context == 'agent':
        validate_agent_command(command_body=command_body)
    else:
        validate_resource_server_command(command_body=command_body)

    return client_context, command_body


def lambda_handler(event, context):
    logger.debug('event: {}'.format(json.dumps(event, default=str)))
    
    client_context = None
    command_body = None
    try:
        client_context, command_body = parse_event(event=event)
    except:
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
        return format_response(status_code=599, body={'error': 'Command Instruction Failed'})

    return format_response(status_code=201, body={'message': 'It Worked!'})
