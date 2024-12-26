import os
import json
import json
import logging
import traceback
import sys
import socket
from email.message import Message

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


def handler(event, context):
    """
        Expected data that this function can react on (example):

            {
                "RecordTtl": 1234567890,
                "CommandOnTtl": "delete_relay_server",
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
                logger.info('Passing data on to command API')
                origin = data.pop('RecordOrigin')
                origin_data = {
                    'command': data['CommandOnTtl'],
                    'body': json.loads(data['RecordValue']),
                }
                # TODO Post to SQS as if it is from the API Gateway.... Mimic the Proxy Request...
                
    return 'ok'