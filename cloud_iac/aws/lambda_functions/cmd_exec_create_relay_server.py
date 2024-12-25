import logging
import os
import sys
import json
import traceback


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


def extract_body_as_dict_from_event_record(record)->dict:
    try:
        return json.loads(record['body'])
    except:
        logger.error('Failed to get body from event: {}'.format(record))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    return dict()


def handler(event, context):
    logger.debug('event: {}'.format(json.dumps(event, default=str)))
    if 'Records' in event:
        for record in event['Records']:
            command_data = extract_body_as_dict_from_event_record(record=record)
            logger.debug('command_data: {}'.format(json.dumps(command_data, default=str)))
    return "ok"

