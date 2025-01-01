import logging
import os
import sys
import json
import copy
import traceback
import boto3
from boto3.dynamodb.conditions import Attr


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


def scan_dynamodb_table(table_name, filter_expression=None, expression_attribute_values=None):
    # This code obtained via Google Gemini - Slightly modified, but seems to work ok
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)
    scan_kwargs = {}
    if filter_expression:
        scan_kwargs['FilterExpression'] = filter_expression
    if expression_attribute_values:
      scan_kwargs['ExpressionAttributeValues'] = expression_attribute_values
    try:
        response = table.scan(**scan_kwargs)
        items = response['Items']
        while 'LastEvaluatedKey' in response:
            scan_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = table.scan(**scan_kwargs)
            items.extend(response['Items'])
        return items, None
    except Exception as e:
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
        return None, str(e)


class CommandConfig:

    def __init__(self):
        self.config = dict()
        self.get_api_command_config_from_dynamodb()

    def get_api_command_config_from_dynamodb(self)->dict:
        self.config = dict()
        filter_expression = Attr('RecordKey').begins_with('config:api-command:')
        items, error = scan_dynamodb_table(table_name='cumulus-tunnel', filter_expression=filter_expression)
        if error:
            logger.error('DynamoDB Scan Error: {}'.format(error))
            raise Exception(error)
        else:
            logger.debug('items: {}'.format(json.dumps(items, default=str)))
            for item in items:
                if 'RecordValue' in item and 'RecordKey' in item:
                    record_key = item['RecordKey']
                    command = record_key.split(':')[-1]
                    if command not in self.config:
                        record_value_data = json.loads(item['RecordValue'])
                        if 'SqsUrl' in record_value_data:
                            self.config[command] = record_value_data['SqsUrl']
        logger.info('CONFIG: {}'.format(json.dumps(self.config, default=str)))
                    

    def get_sqs_url_for_command(self, command: str)->str:
        if command not in self.config:
            self.get_api_command_config_from_dynamodb()
            if command not in self.config:
                raise Exception('Command "{}" not configured'.format(command))
        return self.config[command]


command_config_cache = CommandConfig()


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


def validate_resource_server_command(command_body: dict):
    logger.debug('Validating RESOURCE SERVER command: {}'.format(json.dumps(command_body, default=str)))


def parse_event(event):
    client_context = get_command_agent_context(event=event)
    command_body = get_command_body(event=event)
    if client_context == 'agent':
        validate_agent_command(command_body=command_body)
    else:
        validate_resource_server_command(command_body=command_body)
    return client_context, command_body


def process_command_and_submit_to_sqs(command_body: dict):
    sqs_url = command_config_cache.get_sqs_url_for_command(command=command_body['command'])
    logger.debug('sqs_url: {}'.format(sqs_url))
    client = boto3.client('sqs')
    response = client.send_message(
        QueueUrl=sqs_url,
        MessageBody='{}'.format(json.dumps(command_body['command_parameters']))
    )
    logger.debug('response: {}'.format(json.dumps(response, default=str)))
    logger.info('Message ID: {}'.format(response['MessageId']))
    return format_response(status_code=202, body={'agent-command-response': 'successfully queued command for execution'})


def lambda_handler(event, context):
    logger.debug('event: {}'.format(json.dumps(event, default=str)))
    
    client_context = None
    command_body = None
    try:
        client_context, command_body = parse_event(event=event)
        if 'echo' in command_body:
            logger.info('ECHO command - returning to the client with the submitted text')
            return format_response(status_code=200, body={'echo-response': '{}'.format(command_body['echo'])})
        if client_context is not None:
            return process_command_and_submit_to_sqs(command_body=command_body)
    except:
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))

    return format_response(status_code=599, body={'error': 'Command Instruction Failed'})
