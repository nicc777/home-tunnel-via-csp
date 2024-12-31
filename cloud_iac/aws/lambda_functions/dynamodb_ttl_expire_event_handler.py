import os
import json
import logging
import traceback
import sys
from email.message import Message
import boto3
from boto3.dynamodb.conditions import Attr

URL = os.getenv('URL', 'http://localhost/')
DEBUG = bool(int(os.getenv('DEBUG', '0')))

# TODO get sqs queue info from dynamodb, based on the api command


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


def do_process_record(record)->bool:
    logger.debug('record: {}'.format(json.dumps(record, default=str)))
    try:
        if 'REMOVE' not in record['eventName'].upper():
            return False
        logger.info('Potential record Removal Event detected...')
        if 'dynamodb' in record:
            logger.info('Appears to be a DynamoDB record Removal Event -proceed')
            return True
        logger.warning('This does not look like a DynamoDB Removal Event')
    except:
        logger.error('Unable to parse event - automatically will not qualify')
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    return False


def convert_value_to_number(value:str):
    try:
        return int(value)
    except:
        logger.warning('Value "{}" does not appear to be an INT - attempting a float conversion next...'.format(value))
    return float(value)


def get_dynamodb_deleted_record_as_simple_dict(record)->dict:    
    """
    References:
        * https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes
        * https://blog.awsfundamentals.com/aws-dynamodb-data-types
    Example record:
        {
            ...
            "dynamodb": {
                "ApproximateCreationDateTime": 1735214957,
                "Keys": {
                    ...
                },
                "OldImage": {
                    "RecordTtl": {
                        "N": "1735077600"
                    },
                    "RecordKey": {
                        "S": "TestKey"
                    },
                    "ExampleField": {
                        "S": "Example Value"
                    }
                },
                ...
            },
            ...
        }
    """
    simplified_record = dict()
    dynamodb_record = record['dynamodb']['OldImage']
    for field_name, field_composite_data in dynamodb_record.items():
        for field_value_type, field_value_raw in field_composite_data.items():
            simplified_record[field_name] = '{}'.format(field_value_raw)
            if field_value_type == 'N':
                simplified_record[field_name] = convert_value_to_number(value=field_value_raw)
            elif field_value_type in ('L', 'M', 'SS', 'NS', 'BS',):
                raise Exception('Field type "{}" is not yet supported'.format(field_value_type))
    return simplified_record


def is_command_api_type_record(record: dict)->bool:
    required_records = {
        'RecordTtl': int,
        'CommandOnTtl': str,
        'RecordKey': str,
        'RecordValue': str,
        'RecordOrigin': str,
    }
    for key, expected_type in required_records.items():
        if key not in record:
            logger.warning('Expected key "{}" not present'.format(key))
            return False
        if isinstance(record[key], expected_type) is False:
            logger.warning('Key "{}" type expected to be "{}" but found {}'.format(key, type(expected_type), type(record[key])))
            return False
    return True


def process_command_and_submit_to_sqs(sqs_url: str, command_body: dict):
    logger.debug('sqs_url: {}'.format(sqs_url))
    client = boto3.client('sqs')
    response = client.send_message(
        QueueUrl=sqs_url,
        MessageBody='{}'.format(json.dumps(command_body, default=str))
    )
    logger.debug('response: {}'.format(json.dumps(response, default=str)))
    logger.info('Message ID: {}'.format(response['MessageId']))


def handler(event, context):
    """
        Expected data that this function can react on (example):

            {
                "RecordTtl": 1234567890,
                "CommandOnTtl": "delete_relay_server_stack",
                "RecordKey": "relay-server-stack",
                "RecordValue": "{\"StackName\": \"test-stack\"}",
                "RecordOrigin": "resource"
            }

        FIeld Name      Type    Description
        ----------------------------------------------------------------------------------------------------
        RecordTtl       int     When the record expires
        CommandOnTtl    string  The command to post to the command API
        RecordKey       string  Context of what this record is
        RecordValue     string  Raw data in JSON format which will be forwarded as-is to the command API
        RecordOrigin    string  Value can be "agent" or "resource" depending on the origin
    """
    logger.debug('event: {}'.format(json.dumps(event, default=str)))
    if 'Records' not in event:
        return 'ok'
    for record in event['Records']:
        logger.debug('Evaluating if record must be processed')
        if do_process_record(record=record) is False:
            logger.warning('Ignoring Record')
        else:
            data = get_dynamodb_deleted_record_as_simple_dict(record=record)
            logger.debug('data: {}'.format(json.dumps(data, default=str)))
            if is_command_api_type_record(record=data) is False:
                logger.warning('No data to forward to command API was found')
            else:
                command = data['CommandOnTtl']
                try:
                    sqs_queue = command_config_cache.get_sqs_url_for_command(command=command)
                    logger.info('Passing data for command "{}" on to SQS Queue "{}"'.format(command, sqs_queue))
                    origin_data = {
                        'command': command,
                        'command_parameters': json.loads(data['RecordValue']),
                    }
                    process_command_and_submit_to_sqs(
                        sqs_url=sqs_queue,
                        command_body=origin_data
                    )
                except Exception as e:
                    logger.error('Error: {}'.format(e))
                    logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
                
    return 'ok'