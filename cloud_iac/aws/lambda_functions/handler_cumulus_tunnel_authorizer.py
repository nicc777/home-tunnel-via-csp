"""
See https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html
"""

import logging
import os
import sys
import json
import boto3
import traceback
import base64


DEBUG = bool(int(os.getenv('DEBUG', '0')))
SECRET_ARN = os.getenv('SECRET_ARN', '')


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

# Prevent duplicate log entries
logger.propagate = False


def get_secret()->str:
    try:
        client = boto3.client('secretsmanager')
        secret_id = SECRET_ARN.split('/')[-1]
        response = client.get_secret_value(SecretId=secret_id)
        return '{}'.format(response['SecretString'])
    except:
        logger.error('Failed to retrieve secret value')
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    return ''


def lambda_handler(event, context):
    logger.debug('event: {}'.format(json.dumps(event, default=str)))
    retrieved_secret_json = get_secret()

    secret_data = json.loads(retrieved_secret_json)
    authorizer_string = '{}:{}'.format(secret_data['username'], secret_data['password'])
    required_token_value = base64.b64encode(authorizer_string.encode('utf-8')).decode('utf-8')

    logger.debug('required_token_value LEN = {}'.format(len(retrieved_secret_json)))
    if len(required_token_value) < 8:
        logger.error('unauthorized - Invalid token length from SecretsManager')
        raise Exception('Unauthorized')

    # Retrieve request parameters from the Lambda function input:
    headers = event['headers']
    queryStringParameters = event['queryStringParameters']
    pathParameters = event['pathParameters']
    stageVariables = event['stageVariables']

    # Parse the input for the parameter values
    tmp = event['methodArn'].split(':')
    apiGatewayArnTmp = tmp[5].split('/')
    awsAccountId = tmp[4]
    region = tmp[3]
    restApiId = apiGatewayArnTmp[0]
    stage = apiGatewayArnTmp[1]
    method = apiGatewayArnTmp[2]
    resource = '/'

    logger.debug('VAR headers               : {}'.format(json.dumps(headers, default=str)))
    logger.debug('VAR queryStringParameters : {}'.format(json.dumps(queryStringParameters, default=str)))
    logger.debug('VAR pathParameters        : {}'.format(json.dumps(pathParameters, default=str)))
    logger.debug('VAR stageVariables        : {}'.format(json.dumps(stageVariables, default=str)))
    logger.debug('VAR awsAccountId          : {}'.format(awsAccountId))
    logger.debug('VAR region                : {}'.format(region))
    logger.debug('VAR restApiId             : {}'.format(restApiId))
    logger.debug('VAR stage                 : {}'.format(stage))
    logger.debug('VAR method                : {}'.format(method))
    logger.debug('VAR resource              : {}'.format(resource))
    
    if (apiGatewayArnTmp[3]):
        resource += apiGatewayArnTmp[3]

    origin_token = headers['x-cumulus-tunnel-credentials']
    origin_value = headers['origin']

    # Perform authorization to return the Allow policy for correct parameters
    # and the 'Unauthorized' error, otherwise.

    logger.debug('Comparing tokens: "{}" vs "{}"'.format(origin_token, required_token_value))
    logger.debug('Comparing origin: "{}" in ("agent", "resource")'.format(origin_value))
    if origin_token == required_token_value and origin_value in ('agent', 'resource',):
        response = generateAllow(origin_value, event['methodArn'])
        logger.info('authorized')
        return response
    else:
        logger.error('unauthorized')
        raise Exception('Unauthorized') # Return a 401 Unauthorized response

    # response = generateAllow('me', event['methodArn'])
    # logger.warning('authorized without actual checks')
    # return response

    # Help function to generate IAM policy


def generatePolicy(principalId, effect, resource):
    authResponse = {}
    authResponse['principalId'] = principalId
    if (effect and resource):
        policyDocument = {}
        policyDocument['Version'] = '2012-10-17'
        policyDocument['Statement'] = []
        statementOne = {}
        statementOne['Action'] = 'execute-api:Invoke'
        statementOne['Effect'] = effect
        statementOne['Resource'] = resource
        policyDocument['Statement'] = [statementOne]
        authResponse['policyDocument'] = policyDocument

    authResponse['context'] = {
        "origin": principalId,
    }

    return authResponse


def generateAllow(principalId, resource):
    return generatePolicy(principalId, 'Allow', resource)


def generateDeny(principalId, resource):
    return generatePolicy(principalId, 'Deny', resource)
