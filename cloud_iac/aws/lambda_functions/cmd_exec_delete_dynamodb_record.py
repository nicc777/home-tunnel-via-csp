import logging
import os
import sys
import json
import traceback
import boto3
from boto3.dynamodb.conditions import Attr


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
    

def dynamodb_delete_record(table_name: str, record_key: str, record_ttl: str):
    try:
        client = boto3.client('dynamodb')
        response = client.delete_item(
            TableName=table_name,
            Key={
                'RecordKey': {
                    'S': '{}'.format(record_key)
                },
                'RecordTtl': {
                    'N': '{}'.format(record_ttl)
                },
            },
            ReturnConsumedCapacity='TOTAL'
        )
        logger.info('Deleted key "{}" with TTL "{}"'.format(record_key, record_ttl))
        logger.debug('Response: {}'.format(json.dumps(response, default=str)))
    except Exception as e:
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
        logger.error('FAILED to Delete key "{}" with TTL "{}"'.format(record_key, record_ttl))


def cleanup_record(table_name: str, key_begins_with_string: str):
    filter_expression = Attr('RecordKey').begins_with(key_begins_with_string)
    items, error = scan_dynamodb_table(table_name='cumulus-tunnel', filter_expression=filter_expression)
    if error:
        logger.error('DynamoDB Scan Error: {}'.format(error))
        return
    logger.debug('items: {}'.format(json.dumps(items, default=str)))
    for item in items:
        if 'RecordValue' in item and 'RecordTtl' in item:
            dynamodb_delete_record(
                table_name=table_name,
                record_key='{}'.format(item['RecordKey']),
                record_ttl='{}'.format(item['RecordTtl'])
            )


def extract_body_as_dict_from_event_record(record)->dict:
    try:
        return json.loads(record['body'])
    except:
        logger.error('Failed to get body from event: {}'.format(record))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    return dict()


def extract_record_key(record_value: dict)->tuple:
    record_key = None
    record_ttl = None
    try:
        for item in record_value:
            if 'parameter_name' in item and 'parameter_value' in item:
                if item['parameter_name'] == 'RecordKey':
                    record_key = '{}'.format(item['parameter_value'])
                elif item['parameter_name'] == 'RecordTtl':
                    record_ttl = '{}'.format(item['parameter_value'])
    except Exception as e:
        logger.error('Failed to extract key: {}'.format(str(e)))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    logger.debug('record_key: {}'.format(record_key))
    logger.debug('record_ttl: {}'.format(record_ttl))
    return record_key, record_ttl


def handler(event, context):
    logger.debug('event: {}'.format(json.dumps(event, default=str)))
    if 'Records' in event:
        for record in event['Records']:
            record_key = None
            record_ttl = None
            command_data = extract_body_as_dict_from_event_record(record=record)
            logger.debug('command_data: {}'.format(json.dumps(command_data, default=str)))
            if 'RecordValue' in command_data:
                record_key, record_ttl =  extract_record_key(record_value=command_data['RecordValue'])
            if record_key is not None and record_ttl is not None:
                dynamodb_delete_record(
                    table_name='cumulus-tunnel',
                    record_key=record_key,
                    record_ttl=record_ttl
                )
    elif 'command' in event and 'command_parameters' in event:
        if event['command'] == 'delete_dynamodb_record':
            # TODO - Implement direct call from API
            logger.warning('This is not yet implemented...')
    
    return "ok"

