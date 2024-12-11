import logging
import os
import sys
import json
import traceback


DEBUG = bool(int(os.getenv('DEBUG', '0')))

# Files ending with this string will not be processed, but may be created to store state
STATE_FILE_KEY_EXTENSION = os.getenv('STATE_FILE_KEY', '-tunnel-state.json')

# The S3 bucket for storing state.
STATE_BUCKET = os.getenv('STATE_BUCKET', '')


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
formatter = logging.Formatter('%(asctime)s - %(name)s - %(funcName)s:%(lineno)d -  %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# Silence most of boto3 library logging
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)


def get_sns_record_from_event_record(record: dict)->dict:
    if record is None:
        logger.error('Record cannot be NoneType- ignoring')
        return
    if isinstance(record, dict) is False:
        logger.error('Expected the record to be of type dict - ignoring. Type is {}'.format(type(record)))
        return
    if 'EventSubscriptionArn' not in record:
        logger.error('Record does not contain the key "EventSubscriptionArn" - ignoring')
        return
    if 's3-object-created' not in record['EventSubscriptionArn']:
        logger.error('Expected an S3 object created event from SNS - ignoring')
        return
    if 'Sns' not in record:
        logger.error('Record does not contain the key "Sns" - ignoring')
        return
    if isinstance(record['Sns'], dict) is False:
        logger.error('Expected the SNS record to be of type dict - ignoring. Type is {}'.format(type(record['Sns'])))
        return
    return record['Sns']


def extract_message_from_sns_record(sns: dict)->dict:
    if sns is None:
        logger.error('SNS Record cannot be NoneType- ignoring')
        return
    if 'Message' not in sns:
        logger.error('SNS record does not contain the key "Message" - ignoring')
        return
    if isinstance(sns['Message'], str) is False:
        logger.error('Expected the SNS Message record to be of type str - ignoring. Type is {}'.format(type(sns['Message'])))
        return
    try:
        return json.loads(sns['Message'])
    except:
        logger.error('Failed to convert JSON string to dict')
    return dict()


def validate_basic_records(input_data: dict, expected_key_type: list, key: str='Records')->bool:
    logger.debug('input type: {}   expected_type: {}   input (as_is): {}'.format(type(input_data), type(expected_key_type), input_data))
    if input_data is None:
        logger.error('Input cannot be NoneType- ignoring')
        return False
    if key not in input_data:
        logger.error('Input does not contain the key "{}" - ignoring'.format(key))
        return False
    if input_data[key] is None:
        logger.error('Input key record is NoneType - ignoring')
        return False
    if isinstance(input_data[key], expected_key_type) is False:
        logger.error('Incorrect type. Expected type "{}" but found {}'.format(type(expected_key_type), type(input_data[key])))
        return False
    return True


def extract_bucket(s3_record: dict):
    if validate_basic_records(input_data=s3_record, key='bucket', expected_key_type=dict) is False:
        logger.error('Failed to extract bucket')
        return ''
    if 'name' in s3_record['bucket']:
        return '{}'.format(s3_record['bucket']['name'])
    logger.error('Key "name" for bucket not found - ignoring')
    return ''
    

def extract_key(s3_record: dict):
    if validate_basic_records(input_data=s3_record, key='object', expected_key_type=dict) is False:
        logger.error('Failed to extract key')
        return ''
    if 'key' in s3_record['object']:
        key: str
        key = s3_record['object']['key']
        if key is None:
            logger.error('OOPS: Somehow key is NoneType! - Ignoring')
            return ''
        if isinstance(key, str) is False:
            logger.error('OOPS: Somehow key is not a string! - Ignoring')
            return ''
        if key.startswith('agent-') is False or key.endswith('.json') is False:
            logger.warning('NOT-AN-AGENT-FILE - Ignoring')
            return ''
        return '{}'.format(s3_record['object']['key'])
    logger.error('Key "key" for object not found - ignoring')
    return ''


def process_s3_record(record: dict):
    if validate_basic_records(input_data=record, key='s3', expected_key_type=dict) is False:
        logger.error('Failed to parse message')
        return
    s3_record = record['s3']
    logger.debug('s3_record: {}'.format(json.dumps(s3_record, default=str)))
    bucket = extract_bucket(s3_record=s3_record)
    key = extract_key(s3_record=s3_record)
    if bucket == '' or key == '':
        return
    logger.info('Attempting to parse s3://{}/{}'.format(bucket, key))
    # TODO - Process S3 record


def process_message(message: dict):
    if validate_basic_records(input_data=message, key='Records', expected_key_type=list) is False:
        logger.error('Failed to parse message')
        return
    for record in message['Records']:
        process_s3_record(record=record)


def process_event_records(event: dict):
    if validate_basic_records(input_data=event, key='Records', expected_key_type=list) is False:
        logger.error('Failed to parse event')
        return
    for record in event['Records']:
        sns = get_sns_record_from_event_record(record=record)
        message = extract_message_from_sns_record(sns=sns)
        logger.debug('message_record: {}'.format(json.dumps(message, default=str)))
        process_message(message=message)


def handler(event, context):
    if len(STATE_BUCKET) == 0:
        logger.error('The environment variable STATE_BUCKET *must* be set to a valid S3 bucket name')
    logger.debug('event: {}'.format(json.dumps(event, default=str)))
    process_event_records(event=event)
    return "ok"

