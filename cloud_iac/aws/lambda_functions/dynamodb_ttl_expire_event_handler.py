import os
import json
import typing
import urllib.error
import urllib.parse
import urllib.request
import json
import logging
import traceback
import sys
import socket
from email.message import Message

URL = os.getenv('URL', 'http://localhost/')
DEBUG = bool(int(os.getenv('DEBUG', '0')))
CREDENTIALS_SECRET = os.getenv('CREDENTIALS_SECRET', 'none')
API_KEY = os.getenv('API_KEY', 'none')


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


class Response(typing.NamedTuple):
    body: str
    headers: Message
    status: int
    error_count: int = 0

    def json(self) -> typing.Any:
        try:
            output = json.loads(self.body)
        except json.JSONDecodeError:
            output = ""
        return output

def request(
    url: str,
    data: dict = None,
    params: dict = None,
    headers: dict = None,
    method: str = "GET",
    data_as_json: bool = True,
    error_count: int = 0,
) -> Response:
    # Adapted from https://dev.to/bowmanjd/http-calls-in-python-without-requests-or-other-external-dependencies-5aj1
    if not url.casefold().startswith("http"):
        raise urllib.error.URLError("Incorrect and possibly insecure protocol in url")
    method = method.upper()
    request_data = None
    headers = headers or {}
    data = data or {}
    params = params or {}
    headers = {"Accept": "application/json", **headers}
    if method == "GET":
        params = {**params, **data}
        data = None
    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True, safe="/")
    if data:
        if data_as_json:
            request_data = json.dumps(data).encode()
            headers["Content-Type"] = "application/json; charset=UTF-8"
        else:
            request_data = urllib.parse.urlencode(data).encode()
    logger.debug('url          : {}'.format(url))
    logger.debug('method       : {}'.format(method))
    logger.debug('headers      : {}'.format(headers))
    logger.debug('request_data : {}'.format(request_data))
    hostname = url.split('/')[2]
    logger.debug('DNS          : {}'.format(socket.gethostbyname(hostname)))
    httprequest = urllib.request.Request(
        url, data=request_data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(httprequest) as httpresponse:
            response = Response(
                headers=httpresponse.headers,
                status=httpresponse.status,
                body=httpresponse.read().decode(
                    httpresponse.headers.get_content_charset("utf-8")
                ),
            )
    except urllib.error.HTTPError as e:
        response = Response(
            body=str(e.reason),
            headers=e.headers,
            status=e.code,
            error_count=error_count + 1,
        )
    return response


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


def lookup_dns(hostname: str)->str:
    ip_address = socket.gethostbyname(hostname)


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
                response = request(
                    url=URL,
                    data=origin_data,
                    headers={
                        'x-api-key': API_KEY,
                        'x-cumulus-tunnel-credentials': CREDENTIALS_SECRET,
                        'origin': origin,
                    },
                    method="POST"
                )
                logger.info('Command response: {}'.format(response))
    return 'ok'