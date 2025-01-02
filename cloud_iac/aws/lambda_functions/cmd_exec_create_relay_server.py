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

# Prevent duplicate log entries
logger.propagate = False


def get_deployed_cloudformation_stack_names(next_token: str=None)->list:
    stack_names = list()
    client = boto3.client('cloudformation')
    response = dict()
    if next_token is not None:
        response = client.list_stacks(NextToken=next_token)
    else:
        response = client.list_stacks()
    if 'NextToken' in response:
        stack_names += get_deployed_cloudformation_stack_names(next_token=response['NextToken'])
    if 'StackSummaries' in response:
        for stack_summary in response['StackSummaries']:
            if 'StackName' in stack_summary:
                if 'DELETE' not in stack_summary['StackStatus']:
                    if stack_summary['StackName'] not in stack_names:
                        stack_names.append(stack_summary['StackName'])
                else:
                    logger.info(
                        'Previous version of stack named "{}" found, but ignored as it is in a "{}" state.'.format(
                            stack_summary['StackName'],
                            stack_summary['StackStatus']
                        )
                    )
    logger.debug('stack_names: {}'.format(stack_names))
    return stack_names


def extract_body_as_dict_from_event_record(record)->dict:
    try:
        return json.loads(record['body'])
    except:
        logger.error('Failed to get body from event: {}'.format(record))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    return dict()


def prepare_cloudformation_parameters(command_data: dict)->list:
    parameters = list()
    for record in command_data['StackParameters']:
        parameters.append(
            {
                'ParameterKey': '{}'.format(record['parameter_name']),
                'ParameterValue': '{}'.format(record['parameter_value']),
            }
        )
    return parameters


def create_cloudformation_new_stack(
    template_key: str,
    stack_parameters: list,
    stack_name: str,
    aws_region: str,
    s3_bucket: str
)->str:
    template_url = 'https://{}.s3.{}.amazonaws.com/{}'.format(
        s3_bucket,
        aws_region,
        template_key
    )
    logger.info('Attempting to create a new CloudFormation Stack from template {}'.format(template_url))
    client = boto3.client('cloudformation')
    response = client.create_stack(
        StackName=stack_name,
        TemplateURL=template_url,
        Parameters=stack_parameters,
        TimeoutInMinutes=60,
        Capabilities=[
            'CAPABILITY_IAM',
            'CAPABILITY_NAMED_IAM'
        ],
        OnFailure='DO_NOTHING'
    )
    logger.debug('response: {}'.format(json.dumps(response, default=str)))
    return response['StackId']
    


def handler(event, context):
    logger.debug('event: {}'.format(json.dumps(event, default=str)))
    if 'Records' in event:
        current_deployed_stack_names = get_deployed_cloudformation_stack_names()
        for record in event['Records']:
            command_data = extract_body_as_dict_from_event_record(record=record)
            logger.debug('command_data: {}'.format(json.dumps(command_data, default=str)))

            """
            command_data:
            ------------

                {
                    "StackName": "cumulus-tunnel-relay-server-test-relay-stack",
                    "StackParameters": [
                        {
                            "parameter_name": "ArtifactBucketNameParam",
                            "parameter_type": "str",
                            "parameter_value": "..."
                        },
                        .....
                    ]
                }
            """
            if 'StackName' not in command_data or 'StackParameters' not in command_data:
                raise Exception('Invalid data: {}'.format(command_data))
            if command_data['StackName'] not in current_deployed_stack_names:
                # NEW stack
                logger.info('Creating NEW stack named "{}"'.format(command_data['StackName']))
                stack_id = create_cloudformation_new_stack(
                    template_key='relay_server.yaml',
                    stack_parameters=prepare_cloudformation_parameters(command_data=command_data),
                    stack_name=command_data['StackName'],
                    aws_region=context.invoked_function_arn.split(':')[3],
                    s3_bucket=os.getenv('ARTIFACT_BUCKET')
                )
                logger.info('StackId: {}'.format(stack_id))
            else:
                # CHANGE SET
                logger.info('Creating CHANGE SET for stack named "{}"'.format(command_data['StackName']))


    return "ok"

