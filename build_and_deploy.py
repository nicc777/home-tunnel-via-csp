#!/usr/bin/env python3

import os
import sys
import logging
import argparse
import json
from datetime import datetime, timezone
import time
import traceback
import subprocess
import copy
import tempfile
import base64


parser = argparse.ArgumentParser(
    prog='build_and_deploy',
    description='Tooling for Cloud provisioning of the tunneling solution',
    epilog='Use at your own risk!'
)

parser.add_argument(
    '-v',
    '--verbose',
    help='Enables DEBUG logging',
    action='store_true',
    default=False,
    required=False
)
parser.add_argument(
    '--cloud',
    help='A target cloud environment. Supported options: "aws"',
    action='store',
    type=str,
    dest='target_cloud_sp',
    default='aws',
    required=False
)
parser.add_argument(
    '--artifact_location',
    help='A target location to upload artifacts to, for example an S3 bucket name',
    action='store',
    type=str,
    dest='artifact_location',
    required=True
)
parser.add_argument(
    '--profile',
    help='The cloud profile to use. Processing is based on the implementations of the selected Cloud Service Provider - refer to documentation for more information. For AWS, this is simply the AWS profile name.',
    action='store',
    type=str,
    dest='csp_profile',
    required=True
)
parser.add_argument(
    '--region',
    help='The cloud region to use. Refer to the specific Cloud Service Provider documentation for valid region values.',
    action='store',
    type=str,
    dest='csp_region',
    required=True
)
parser.add_argument(
    '--extra_vm_setup',
    help='The optional custom setup script to be run when the tunnel VM starts up. Must be a SHELL script, if supplied.',
    action='store',
    type=str,
    dest='extra_vm_setup',
    required=False,
    default='cloud_iac/aws/ec2_setup_scripts/additional-setup.sh'
)
parser.add_argument(
    '--param_vpc_id',
    help='The VPC ID to be used. This is where the relay server will be deployed in.',
    action='store',
    type=str,
    dest='param_vpc_id',
    required=True
)
parser.add_argument(
    '--param_vpc_cidr',
    help='The CIDR address of the VPC',
    action='store',
    type=str,
    dest='param_vpc_cidr',
    required=True
)
parser.add_argument(
    '--param_public_subnet_1_id',
    help='ID of public Subnet 1 in the VPC',
    action='store',
    type=str,
    dest='param_public_subnet_id_1',
    required=True
)
parser.add_argument(
    '--param_public_subnet_2_id',
    help='ID of public Subnet 2 in the VPC',
    action='store',
    type=str,
    dest='param_public_subnet_id_2',
    required=True
)
parser.add_argument(
    '--param_public_subnet_3_id',
    help='ID of public Subnet 3 in the VPC',
    action='store',
    type=str,
    dest='param_public_subnet_id_3',
    required=True
)
parser.add_argument(
    '--param_relay_vm_identifier',
    help='The VM image ID. For AWS this must be an AMI to use',
    action='store',
    type=str,
    dest='param_relay_vm_identifier',
    required=True
)
parser.add_argument(
    '--param_base_domain_name',
    help='The domain name for creating records. You MUST own and control this domain.',
    action='store',
    type=str,
    dest='param_base_domain_name',
    required=True
)
parser.add_argument(
    '--param_aws_route53_zone_id',
    help='The AWS Route 53 Zone ID. For now, this parameter is required, but this may change in the future when more cloud providers are supported.',
    action='store',
    type=str,
    dest='param_aws_route53_zone_id',
    required=True
)
parser.add_argument(
    '--param_aws_acm_arn',
    help='The AWS ACM Certificate ARN for the selected domain (typically a wild-card certificate). For now, this parameter is required, but this may change in the future when more cloud providers are supported.',
    action='store',
    type=str,
    dest='param_aws_acm_arn',
    required=True
)


args = parser.parse_args()
DEBUG = args.verbose

#region logger

logger = logging.getLogger('cumulus_tunnel_build_and_deploy')
logger.setLevel(logging.INFO)
if DEBUG is True:
    logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
if DEBUG is True:
    ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(funcName)s:%(lineno)d - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


#endregion logger

def run_shell_script(script_path, *args):
  try:
    result = subprocess.run(
        [script_path] + list(args), 
        capture_output=True, 
        check=True, 
        text=True
    )
    return result.stdout.strip()
  except subprocess.CalledProcessError as e:
    raise RuntimeError(f"Error executing script '{script_path}' with args: {args}: {e}")


def load_json_file(file)->dict:
    with open(file, 'r') as f:
        return json.loads(f.read())


class CloudServiceProviderBase:

    def __init__(self, args):
        self.args = args
        self.validate_args()

    def validate_args(self):
        raise Exception('Must be implemented by CSP class')

    def build(self):
        raise Exception('Must be implemented by CSP class')
    
    def _prep_cloud_serverless_functions(self):
        raise Exception('Must be implemented by CSP class')
    
    def upload_artifact(self, source_file: str, destination: dict):
        raise Exception('Must be implemented by CSP class')

    def deploy(self):
        raise Exception('Must be implemented by CSP class')
    
    def refresh_vm(self):
        raise Exception('Must be implemented by CSP class')
    
    def prep_iac_parameters(self, target:str=None, target_id:str=None, additional_parameters: dict=dict()):
        raise Exception('Must be implemented by CSP class')


class AwsCloudServiceProvider(CloudServiceProviderBase):

    def __init__(self, args):
        logger.info('Target AWS')
        super().__init__(args)
        self.stack_outputs = list()
        self.current_cloudformation_stacks = self._list_cloudformation_stacks()
        import boto3
        import boto3.session
        self.session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)

    def prep_iac_parameters(self, target:str=None, target_id:str=None, additional_parameters: list=list()):
        parameters = copy.deepcopy(additional_parameters)
        # Adding standard parameters
        parameters.append(
            {
                "ParameterKey": "ArtifactBucketNameParam",
                "ParameterValue": self.args.artifact_location,
            }
        )
        parameters.append(
            {
                "ParameterKey": "VpcId1Param",
                "ParameterValue": self.args.param_vpc_id
            }
        )
        parameters.append(
            {
                "ParameterKey": "VpcCidrParam",
                "ParameterValue": self.args.param_vpc_cidr
            }
        )
        parameters.append(
            {
                "ParameterKey": "SubnetId1Param",
                "ParameterValue": self.args.param_public_subnet_id_1
            }
        )
        parameters.append(
            {
                "ParameterKey": "SubnetId2Param",
                "ParameterValue": self.args.param_public_subnet_id_2
            }
        )
        parameters.append(
            {
                "ParameterKey": "SubnetId3Param",
                "ParameterValue": self.args.param_public_subnet_id_3
            }
        )
        # Write parameters JSON file
        if os.path.exists(target) is True:
            os.unlink(target)
        with open(target, 'w') as f:
            f.write(json.dumps(parameters))
        logger.info('Written parameters file for CloudFormation template to file "{}"'.format(target))

    def _list_cloudformation_stacks(self, next_token: str=None)->list:
        stack_names = list()
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        client = session.client('cloudformation')
        response = dict()
        if next_token is not None:
            response = client.list_stacks(NextToken=next_token)
        else:
            response = client.list_stacks()
        if 'NextToken' in response:
            stack_names += self._list_cloudformation_stacks(next_token=response['NextToken'])
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
        return stack_names

    def validate_args(self):
        logger.info('Validating values...')
        logger.info('Validating basic AWS S3 access...')
        self.upload_artifact(
            source_file='cloud_iac/aws/ec2_setup_scripts/cumulus-tunnel-setup.sh',
            destination={
                'bucket_name': self.args.artifact_location,
                'key': 'cumulus-tunnel-setup.sh',
            }
        )
        logger.info('Artifact upload to S3 works!')

    def build(self):
        self.upload_artifact(
            source_file=self.args.extra_vm_setup,
            destination={
                'bucket_name': self.args.artifact_location,
                'key': 'additional-setup.sh',
            }
        )
        file_name, package_name = self._package_lambda_function(source_file='cloud_iac/aws/lambda_functions/dynamodb_ttl_expire_event_handler.py')
        logger.debug('DynamoDB Lambda Function: file_name    : {}'.format(file_name))
        logger.debug('DynamoDB Lambda Function: package_name : {}'.format(package_name))

    def upload_artifact(self, source_file: str, destination: dict):
        logger.debug('\t source_file : {}'.format(source_file))
        logger.debug('\t destination : {}'.format(json.dumps(destination, default=str)))
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        s3 = session.client('s3')
        s3.upload_file(source_file, destination['bucket_name'], destination['key'])
        logger.info('Uploaded file {} to s3://{}/{}'.format(source_file, destination['bucket_name'], destination['key']))

    def _delete_change_set(self, change_set_id: str):
        logger.info('Deleting Change Set {}'.format(change_set_id))
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        client = session.client('cloudformation')
        client.delete_change_set(
            ChangeSetName=change_set_id
        )

    def _execute_change_set(self, change_set_id: str):
        logger.info('Executing Change Set {}'.format(change_set_id))
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        client = session.client('cloudformation')
        client.execute_change_set(
            ChangeSetName=change_set_id
        )

    def _wait_for_change_set_status_complete(self, change_set_id: str, next_token: str=None, try_count: int=0, max_tries: int=100, sleep_interval_seconds: int=10)->str:
        counter = try_count + 1
        if counter > max_tries:
            raise Exception('Maximum attempts reached')
        logger.info('Checking Change Set status... Try number {} (max={})'.format(counter, max_tries))
        logger.debug('change_set_id: {}'.format(change_set_id))
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        client = session.client('cloudformation')
        response = dict()
        if next_token is not None:
            response = client.describe_change_set(
                ChangeSetName=change_set_id,
                NextToken=next_token
            )
        else:
            response = client.describe_change_set(
                ChangeSetName=change_set_id
            )
        execution_status = 'UNKNOWN'
        status = 'UNKNOWN'
        status_reason = ''
        if 'ExecutionStatus' in response:
            logger.info('\t ExecutionStatus : {}'.format(response['ExecutionStatus']))
            execution_status = response['ExecutionStatus']
        if 'Status' in response:
            logger.info('\t Status          : {}'.format(response['Status']))
            status = response['Status']
        if 'StatusReason' in response:
            logger.info('\t StatusReason    : {}'.format(response['StatusReason']))
            status_reason = response['StatusReason']
        if 'Changes' in response:
            qty_changes = len(response['Changes'])
            logger.info('\t Qty Changes     : {}'.format(qty_changes))
        if 'NextToken' in response:
            logger.warning('Ignoring NextToken for now...')
        if execution_status == 'UNAVAILABLE' and status == 'FAILED':
            if 'The submitted information didn\'t contain changes' in status_reason:
                self._delete_change_set(change_set_id=change_set_id)
                return
        elif execution_status == 'AVAILABLE' and status == 'CREATE_COMPLETE':
           self._execute_change_set(change_set_id=change_set_id)
        elif execution_status == 'EXECUTE_COMPLETE' and status == 'CREATE_COMPLETE':
            logger.info('All changes applied successfully')
            return
        elif 'FAIL' in execution_status or 'FAIL' in status:
            logger.error('ChangeSet FAILED - check console for details')
            raise Exception('ChangeSet FAILED - check console for details')
        logger.info('\t Sleeping for {} seconds'.format(sleep_interval_seconds))
        time.sleep(sleep_interval_seconds)
        self._wait_for_change_set_status_complete(
            change_set_id=change_set_id,
            next_token=next_token,
            try_count=counter,
            max_tries=max_tries,
            sleep_interval_seconds=sleep_interval_seconds
        )

    def _wait_for_stack_create_status_complete(self, stack_name: str, next_token: str=None, try_count: int=0, max_tries: int=100, sleep_interval_seconds: int=30)->str:
        counter = try_count + 1
        if counter > max_tries:
            raise Exception('Maximum attempts reached')
        logger.info('Checking status... Try number {} (max={})'.format(counter, max_tries))
        logger.debug('stack_name: {}'.format(stack_name))
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        client = session.client('cloudformation')
        response = dict()
        if next_token is not None:
            response = client.describe_stacks(
                StackName=stack_name,
                NextToken=next_token
            )
        else:
            response = client.describe_stacks(
                StackName=stack_name
            )
        logger.debug('response: {}'.format(json.dumps(response, default=str)))
        status = 'UNKNOWN'
        if 'NextToken' in response:
            logger.warning('Ignoring NextToken for now...')
        if 'Stacks' in response:
            for stack in response['Stacks']:
                if 'StackName' in stack:
                    if stack['StackName'] == stack_name:
                        if 'StackStatus' in stack:
                            logger.info('\t StackStatus       : {}'.format(stack['StackStatus']))
                            status = stack['StackStatus']
                        else:
                            logger.warning('Did NOT find "StackStatus" field in stack: {}'.format(json.dumps(stack, default=str)))
                        if 'StackStatusReason' in stack:
                            logger.info('\t StackStatusReason : {}'.format(stack['StackStatusReason']))
                        if 'FAIL' in status or 'DELETE' in status:
                            raise Exception('Failed to create stack - please check the console for details.')
                        elif 'COMPLETE' in status:
                            logger.info('Stack created successfully')
                            return
                    else:
                        logger.warning('Ignoring stack named "{}"...'.format(stack['StackName']))
                else:
                    raise Exception('Expected the field "StackName" in stack: {}'.format(stack))
        else:
            raise Exception('Unrecognized response: {}'.format(response))
        logger.info('\t Sleeping for {} seconds'.format(sleep_interval_seconds))
        time.sleep(sleep_interval_seconds)
        self._wait_for_stack_create_status_complete(
            stack_name=stack_name,
            next_token=next_token,
            try_count=counter,
            max_tries=max_tries,
            sleep_interval_seconds=sleep_interval_seconds
        )

    def _create_cloudformation_new_stack(self, template_key: str, parameter_values_file: str, stack_name: str):
        logger.info('Attempting to create a new CloudFormation Stack')
        template_url = 'https://{}.s3.{}.amazonaws.com/{}'.format(
            self.args.artifact_location,
            self.args.csp_region,
            template_key
        )
        logger.debug('template_url: {}'.format(template_url))
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        client = session.client('cloudformation')
        response = client.create_stack(
            StackName=stack_name,
            TemplateURL=template_url,
            Parameters=load_json_file(file='{}'.format(parameter_values_file)),
            TimeoutInMinutes=60,
            Capabilities=[
                'CAPABILITY_IAM',
                'CAPABILITY_NAMED_IAM'
            ],
            OnFailure='DO_NOTHING'
        )
        logger.debug('response: {}'.format(json.dumps(response, default=str)))
        self._wait_for_stack_create_status_complete(stack_name=stack_name)

    def _create_cloudformation_change_set(self, template_key: str, parameter_values_file: str, stack_name: str):
        logger.info('Attempting to create a CloudFormation Change Set')
        template_url = 'https://{}.s3.{}.amazonaws.com/{}'.format(
            self.args.artifact_location,
            self.args.csp_region,
            template_key
        )
        logger.debug('template_url: {}'.format(template_url))
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        client = session.client('cloudformation')
        response = client.create_change_set(
            StackName=stack_name,
            TemplateURL=template_url,
            Parameters=load_json_file(file='{}'.format(parameter_values_file)),
            Capabilities=[
                'CAPABILITY_IAM',
                'CAPABILITY_NAMED_IAM'
            ],
            OnStackFailure='DO_NOTHING',
            ChangeSetName='changeset-{}'.format(int(datetime.now(tz=timezone.utc).timestamp())),
            Description='Change set from build script on {}'.format(datetime.now(tz=timezone.utc).isoformat()),
            ChangeSetType='UPDATE'
        )
        logger.debug('response: {}'.format(json.dumps(response, default=str)))
        if 'Id' not in response:
            raise Exception('Appears that the change-set failed to create')
        change_set_id = response['Id']
        self._wait_for_change_set_status_complete(change_set_id=change_set_id)

    def _package_lambda_function(self, source_file: str)->tuple:
        package_name = source_file.split('/')[-1].split('.')[0]
        file_name = None
        success = True
        try:
            script_output = run_shell_script(
                "bash",
                "./scripts/package_lambda_function.sh",
                "-f",
                source_file,
                "-p",
                package_name,
            )
            for line in script_output.split('\n'):
                if 'Package File' in line:
                    package_file = line.split(':')[1].strip()
                    file_name = package_file.split(os.sep)[-1]
                    logger.debug('Lambda Package:')
                    logger.debug('\t package_file : {}'.format(package_file))
                    logger.debug('\t file_name    : {}'.format(file_name))
                    artifacts_to_copy = dict()
                    artifacts_to_copy['bucket_name'] = self.args.artifact_location
                    artifacts_to_copy['key'] = file_name
                    self.upload_artifact(
                        source_file=package_file,
                        destination=artifacts_to_copy
                    )
        except RuntimeError as e:
            logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
            success = False
        if success is False:
            raise Exception('Failed to run required lambda prep script "{}"'.format(source_file))
        return file_name, package_name

    def _deploy_sqs_and_lambda_functions(self):
        LAMBDA_FUNCTIONS = [
            'cloud_iac/aws/lambda_functions/cmd_exec_create_relay_server.py',
        ]
        for source_file in LAMBDA_FUNCTIONS:
            file_name, package_name = self._package_lambda_function(source_file=source_file)
            handler_name = '{}.handler'.format(package_name)
            api_command = package_name.replace('cmd_exec_', '') # example: cmd_exec_create_relay_server -> create_relay_server
            stack_name = 'cumulus-tunnel-sqs-lambda-{}-stack'.format(api_command)
            stack_name = stack_name.replace('_', '-')
            parameters_file = '{}{}{}_parameters.json'.format(tempfile.gettempdir(), os.sep, package_name)
            self.prep_iac_parameters(
                target=parameters_file,
                target_id='sqs_and_lambda_command_pair',
                additional_parameters=[
                    {
                        "ParameterKey": "LambdaFunctionS3KeyParam",
                        "ParameterValue": file_name
                    },
                    {
                        "ParameterKey": "PythonHandlerParam",
                        "ParameterValue": handler_name
                    },
                    
                    {
                        "ParameterKey": "QueueNameParam",
                        "ParameterValue": '{}_queue'.format(package_name)
                    },
                    {
                        "ParameterKey": "DebugParam",
                        "ParameterValue": "1"
                    },
                    {
                        "ParameterKey": "ApiCommandParam",
                        "ParameterValue": api_command
                    },
                ]
            )
            if stack_name in self.current_cloudformation_stacks:
                # CHANGE SET
                self._create_cloudformation_change_set(
                    template_key='sqs_and_lambda_command_pair.yaml',
                    parameter_values_file=parameters_file,
                    stack_name=stack_name
                )
            else:
                # CREATE NEW
                self._create_cloudformation_new_stack(
                    template_key='sqs_and_lambda_command_pair.yaml',
                    parameter_values_file=parameters_file,
                    stack_name=stack_name
                )
            new_outputs = self._get_stack_outputs(stack_name=stack_name)
            logger.debug('new_outputs: {}'.format(new_outputs))
            self.stack_outputs += new_outputs

    def _deploy_api_resources(self):
        LAMBDA_FUNCTIONS = [
            'cloud_iac/aws/lambda_functions/handler_cumulus_tunnel_authorizer.py:CumulusTunnelApiAuthorizerS3KeyParam',
            'cloud_iac/aws/lambda_functions/handler_cumulus_tunnel_commander.py:CumulusTunnelCommanderS3KeyParam',
        ]
        additional_parameters = list()
        for function_data in LAMBDA_FUNCTIONS:
            source_file = function_data.split(':')[0]
            function_key_parameter_name = function_data.split(':')[1]
            file_name, package_name = self._package_lambda_function(source_file=source_file)
            additional_parameters.append(
                {
                    "ParameterKey": function_key_parameter_name,
                    "ParameterValue": file_name
                },
            )
        additional_parameters.append(
            {
                "ParameterKey": "DebugParam",
                "ParameterValue": "1"
            },
        )

        parameters_file = '{}{}cumulus_tunnel_api_resources_parameters.json'.format(tempfile.gettempdir(), os.sep)
        stack_name = 'cumulus-tunnel-api-resources-stack'
        
        self.prep_iac_parameters(
            target=parameters_file,
            target_id='cumulus-tunnel-api-resources-stack',
            additional_parameters=additional_parameters
        )
        if stack_name not in self.current_cloudformation_stacks:
            self._create_cloudformation_new_stack(
                template_key='tunnel_resources.yaml',
                parameter_values_file=parameters_file,
                stack_name=stack_name
            )
        else:
            self._create_cloudformation_change_set(
                template_key='tunnel_resources.yaml',
                parameter_values_file=parameters_file,
                stack_name=stack_name
            )
        new_outputs = self._get_stack_outputs(stack_name=stack_name)
        logger.debug('new_outputs: {}'.format(new_outputs))
        self.stack_outputs += new_outputs

    def deploy(self):
        self._deploy_sqs_and_lambda_functions()
        self._deploy_api_resources()
        self._set_dynamodb_lambda_function_additional_environment_variables()
        logger.info('OUTPUTS:')
        for output in self.stack_outputs:
            output_key = None
            output_value = None
            description = 'No Description'
            export_name = '-'
            if 'OutputKey' in output and 'OutputValue' in output:
                output_key = output['OutputKey']
                output_value = output['OutputValue']
                if 'Description' in output:
                    description = output['Description']
                if 'ExportName' in output:
                    if output['ExportName'] is not None:
                        export_name = output['ExportName']
                if output_key is not None and output_value is not None:
                    logger.info(
                        '  * {} = "{}"   [export="{}"] - {}'.format(
                            output_key,
                            output_value,
                            export_name,
                            description
                        )
                    )

    def _get_stack_outputs(self, stack_name: str, next_token: str=None)->list:
        logger.debug('Retrieving outputs for stack "{}"'.format(stack_name))
        outputs = list()
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        client = session.client('cloudformation')
        response = dict()
        if next_token is not None:
            response = client.describe_stacks(
                StackName=stack_name,
                NextToken=next_token
            )
        else:
            response = client.describe_stacks(StackName=stack_name)
        logger.debug('response={}'.format(json.dumps(response, default=str)))
        if 'NextToken' in response:
            data = self._get_stack_outputs(next_token=response['NextToken'])
            outputs += data
        if 'Stacks' in response:
            for stack in response['Stacks']:
                if 'StackName' in stack:
                    if stack['StackName'] == stack_name:
                        if 'Outputs' in stack:
                            outputs = stack['Outputs']
        return outputs

    def get_output_value_from_key(self, key: str)->str:
        value = None
        for output in self.stack_outputs:
            if 'OutputKey' in output and 'OutputValue' in output:
                if output['OutputKey'] == key:
                    value = output['OutputValue']
        return value
    
    def _get_current_lambda_environment_variables(self, function_name: str)->dict:
        environment_variables = dict()
        client = self.session.client('lambda')
        response = client.get_function_configuration(
            FunctionName=function_name
        )
        if 'Environment' in response:
            if 'Variables' in response['Environment']:
                for key,val in response['Environment']['Variables'].items():
                    environment_variables[key] = '{}'.format(val)

        return environment_variables
    
    def _get_current_lambda_complete_configuration(self, function_name: str)->dict:
        current_configuration = dict()
        client = self.session.client('lambda')
        response = client.get_function_configuration(FunctionName=function_name)
        keys_to_copy = (
            'Role',
            'Handler',
            'Description',
            'Timeout',
            'MemorySize',
            'VpcConfig',
            'Environment',
            'Runtime',
            'DeadLetterConfig',
            'KMSKeyArn',
            'TracingConfig',
            'RevisionId',
            'Layers',
            'FileSystemConfigs',
            'ImageConfig',
            'EphemeralStorage',
            'SnapStart',
            'LoggingConfig',
        )
        for key in keys_to_copy:
            if key in response:
                current_configuration[key] = response[key]
        return current_configuration

    def _get_stack_identifiers(self, name: str='cumulus-tunnel-api-resources-stack', next_token: str=None)->list:
        stack_identifiers = list()
        client = self.session.client('cloudformation')
        response = dict()
        if next_token is not None:
            response = client.list_stacks(NextToken=next_token)
        else:
            response = client.list_stacks()
        if 'NextToken' in response:
            stack_identifiers += self._get_stack_identifiers(name=name, next_token=response['NextToken'])
        if 'StackSummaries' in response:
            for data in response['StackSummaries']:
                if name in data['StackName']:
                    record = dict()
                    record['StackId'] = data['StackId']
                    record['StackName'] = data['StackName']
                    record['StackStatus'] = data['StackStatus']
                    record['CreationTime'] = data['CreationTime']
                    # logger.debug('INTERIM data: {}'.format(json.dumps(record, default=str)))
                    stack_identifiers.append(record)
        logger.info('Retrieved {} stacks'.format(len(stack_identifiers)))
        return stack_identifiers


    def _parse_and_get_most_recent_stack(self, stack_identifiers: list)->dict:
        current_stack_identifier_record = dict()
        for stack in stack_identifiers:
            if len(current_stack_identifier_record) == 0:
                current_stack_identifier_record = copy.deepcopy(stack)
            else:
                if stack['CreationTime'] > current_stack_identifier_record['CreationTime']:
                    current_stack_identifier_record = copy.deepcopy(stack)
        return current_stack_identifier_record


    def _get_cloudformation_resources(self, stack_name: str, next_token: str=None)->list:
        resources = list()
        client = self.session.client('cloudformation')
        response = dict()
        if next_token is not None:
            response = client.list_stack_resources(StackName=stack_name, NextToken=next_token)
        else:
            response = client.list_stack_resources(StackName=stack_name)
        if 'NextToken' in response:
            resources += self._get_cloudformation_resources(stack_name=stack_name, next_token=response['NextToken'])
        if 'StackResourceSummaries' in response:
            for data in response['StackResourceSummaries']:
                record = dict()
                record['LogicalResourceId'] = data['LogicalResourceId']
                record['PhysicalResourceId'] = data['PhysicalResourceId']
                record['ResourceStatus'] = data['ResourceStatus']
                resources.append(record)
        return resources


    def _get_resource_physical_id(self, logical_id: str, resources: list)->tuple:
        for record in resources:
            if record['LogicalResourceId'] == logical_id:
                return record['PhysicalResourceId'], record['ResourceStatus']


    def _get_api_token(self, api_key_id: str):
        client = self.session.client('apigateway')
        response = client.get_api_key(
            apiKey=api_key_id,
            includeValue=True
        )
        return response['value']


    def _get_secret_value(self, secret_id: str)->str:
        client = self.session.client('secretsmanager')
        response = client.get_secret_value(SecretId=secret_id)
        return response['SecretString']

    def _set_dynamodb_lambda_function_additional_environment_variables(self):
        """
            This is done because:

                * The Lambda function is in a VPC and as such:
                    * AWS API calls must be facilitated through VPC EndPoints

            Since VPC EndPoints are relatively expensive, and because the data is static, 
            it is more cost efficient to get the data now and manually update the deployed 
            Lambda function environment variables via the AWS API's
        """
        lambda_function_name = 'cumulus-tunnel-dynamodb-ttl-handler'
        #lambda_function_configuration = self._get_current_lambda_complete_configuration(function_name=lambda_function_name)
        lambda_function_environment_variables = self._get_current_lambda_environment_variables(function_name=lambda_function_name)
        if 'CREDENTIALS_SECRET' in lambda_function_environment_variables:
            lambda_function_environment_variables.pop('CREDENTIALS_SECRET')
        if 'API_KEY' in lambda_function_environment_variables:
            lambda_function_environment_variables.pop('API_KEY')

        stack_identifiers = self._get_stack_identifiers()
        most_recent_stack = self._parse_and_get_most_recent_stack(stack_identifiers=stack_identifiers)
        logger.debug('most_recent_stack: {}'.format(json.dumps(most_recent_stack, default=str)))
        resources = self._get_cloudformation_resources(stack_name=most_recent_stack['StackName'])
        logger.debug('resources: {}'.format(json.dumps(resources, default=str)))
        api_key_logical_id, api_key_resource_status = self._get_resource_physical_id(
            logical_id='ApiKey', 
            resources=resources
        )
        logger.debug('API Key "{}" has status "{}"'.format(api_key_logical_id, api_key_resource_status))
        api_gateway_stage_token = self._get_api_token(api_key_id=api_key_logical_id)
        logger.info('HEADER: x-api-key: {}'.format(api_gateway_stage_token))
        secrets_manager_logical_id, secrets_manager_resource_status = self._get_resource_physical_id(
            logical_id='CumulusTunnelAuthTokenSecret', 
            resources=resources
        )
        logger.debug('SecretsManager "{}" has status "{}"'.format(secrets_manager_logical_id, secrets_manager_resource_status))
        secret_value = self._get_secret_value(secret_id=secrets_manager_logical_id)
        logger.debug('secret_value: {}'.format(secret_value))
        secret_data = json.loads(secret_value)
        authorizer_string = '{}:{}'.format(secret_data['username'], secret_data['password'])
        base64_string = base64.b64encode(authorizer_string.encode('utf-8')).decode('utf-8')
        logger.info('HEADER x-cumulus-tunnel-credentials: {}'.format(base64_string))

        lambda_function_environment_variables['CREDENTIALS_SECRET'] = base64_string
        lambda_function_environment_variables['API_KEY'] = api_gateway_stage_token

        # Update Environment Variables....
        client = self.session.client('lambda')
        response = client.update_function_configuration(
            FunctionName=lambda_function_name,
            Environment={
                'Variables': lambda_function_environment_variables
            }
        )

        logger.debug('response: {}'.format(json.dumps(response, default=str, indent=4)))



SUPPORTED_CLOUD_SERVICE_PROVIDERS = {
    'aws': AwsCloudServiceProvider
}
ARTIFACT_FILES = {
    # Local File                                                        Remote KEY
    'tunnel_instance/etc/nginx/sites-enabled/admin'                 :   'etc/nginx/sites-enabled/admin',
    'tunnel_instance/var/www/html/index.html'                       :   'var/www/html/index.html',
    'cloud_iac/aws/cloudformation/relay_server.yaml'                :   'relay_server.yaml',
    'cloud_iac/aws/cloudformation/sqs_and_lambda_command_pair.yaml' :   'sqs_and_lambda_command_pair.yaml',
    'cloud_iac/aws/cloudformation/tunnel_resources.yaml'            :   'tunnel_resources.yaml',
}


def upload_additional_artifact_files(sp_class_instance: CloudServiceProviderBase):
    for local_file, key in ARTIFACT_FILES.items():
        sp_class_instance.upload_artifact(
            source_file=local_file,
            destination={
                'bucket_name': sp_class_instance.args.artifact_location,
                'key': key,
            }
        )


def main():
    if args.target_cloud_sp in SUPPORTED_CLOUD_SERVICE_PROVIDERS:
        sp_class: CloudServiceProviderBase
        sp_class = SUPPORTED_CLOUD_SERVICE_PROVIDERS[args.target_cloud_sp]
        sp_class_instance: CloudServiceProviderBase
        sp_class_instance = sp_class(args=args)
        logger.info('Uploading supplementary artifacts')
        upload_additional_artifact_files(sp_class_instance=sp_class_instance)
        logger.info('Building packages and preparing artifacts')
        sp_class_instance.build()
        sp_class_instance.deploy()
    else:
        logger.error(
            'Cloud Service Provider "{}" not yet implemented or supported. Supported options: {}'.format(
                args.target_cloud_sp,
                ", ".join(list(SUPPORTED_CLOUD_SERVICE_PROVIDERS.keys())) 
            )
        )


if __name__ == '__main__':
    main()



