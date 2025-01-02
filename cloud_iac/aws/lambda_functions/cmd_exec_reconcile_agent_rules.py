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


def get_records_from_dynamodb(table_name: str, key_begins_with: str):
    logger.info('Getting records from table "{}" with key starting with "{}"'.format(table_name, key_begins_with))
    filter_expression = Attr('RecordKey').begins_with(key_begins_with)
    items, error = scan_dynamodb_table(table_name=table_name, filter_expression=filter_expression)
    if error is not None:
        logger.error(
            'Error while retrieving records with key starting with "{}": {}'.format(
                key_begins_with,
                error
            )
        )
        return None
    return items


def extract_records(event)->list:
    records = list()
    try:
        if 'Records' in event:
            for record in event['Records']:
                if 'body' in record:
                    records.append(json.loads(record['body']))
    except Exception as e:
        logger.error('Failed to parse event and extract records: {}'.format(str(e)))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    return records


def get_records(relay_id: str, key_begins_with:str)->list:
    final_key_begins_with = '{}:{}'.format(key_begins_with,relay_id)
    final_key_begins_with = final_key_begins_with.replace('::', ':')
    dynamo_db_records = get_records_from_dynamodb(
        table_name='cumulus-tunnel',
        key_begins_with='{}'.format(final_key_begins_with)
    )
    if dynamo_db_records is not None:
        logger.debug('dynamo_db_records: {}'.format(json.dumps(dynamo_db_records, default=str)))
    else:
        logger.error('None value returned for relay "{}". Skipping.'.format(relay_id))
        return dict()
    return dynamo_db_records


def get_latest_record(records: list)->dict:
    latest_record = dict()
    for record in records:
        if len(latest_record) == 0:
            latest_record = copy.deepcopy(record)
            logger.debug('Setting latest record: {}'.format(json.dumps(record, default=str)))
        else:
            if record['RecordTtl'] > latest_record['RecordTtl']:
                latest_record = copy.deepcopy(record)
                logger.debug('Found newer record: {}'.format(json.dumps(record, default=str)))
            else:
                logger.warning('Ignoring older record: {}'.format(json.dumps(record, default=str)))
    logger.debug('Final latest_record: {}'.format(json.dumps(latest_record, default=str)))
    return latest_record


def attempt_to_convert_str_to_dict(possible_json_data: str)->dict:
    try:
        return json.loads(possible_json_data)
    except:
        pass
    return None


def get_instance_id_and_security_group(instance_id_records: list, security_group_records: list)->tuple:
    instance_id = None
    security_group_id = None

    try:
        instance_id_record = get_latest_record(records=instance_id_records)
        instance_id_record_value = attempt_to_convert_str_to_dict(possible_json_data=instance_id_record['RecordValue'])
        instance_id = instance_id_record_value['InstanceId']

        security_group_record = get_latest_record(records=security_group_records)
        security_group_record_value = attempt_to_convert_str_to_dict(possible_json_data=security_group_record['RecordValue'])
        security_group_id = security_group_record_value['SecurityGroupId']

    except Exception as e:
        logger.error('Failed to parse data: {}'.format(str(e)))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))

    return instance_id, security_group_id


def handler(event, context):
    logger.debug('event: {}'.format(json.dumps(event, default=str)))
    for record in extract_records(event=event):
        logger.debug('Processing record: {}'.format(json.dumps(record, default=str)))
        instance_id_records = get_records(relay_id=record['TargetRelayId'], key_begins_with='relay-server:instance-id:')
        security_group_records = get_records(relay_id=record['TargetRelayId'], key_begins_with='relay-server:security-group:')
        if len(instance_id_records) == 0 or len(security_group_records) == 0:
            logger.error('No records for relay "{}" found. Skipping.'.format(record['TargetRelayId']))
            continue
        
        instance_id, security_group_id = get_instance_id_and_security_group(
            instance_id_records=instance_id_records,
            security_group_records=security_group_records
        )
        
        logger.info('Latest instance ID is "{}" with security group ID: "{}"'.format(instance_id, security_group_id))
    return "ok"

