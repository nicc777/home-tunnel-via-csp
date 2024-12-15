#!/usr/bin/env python3

import os
import sys
import logging
import argparse
import json
import traceback
import subprocess


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
    '--values',
    help='The values to pass for the IaC function for the specified Cloud Service Provider implementation. For AWS, this is the JSON parameters file for the CloudFormation template.',
    action='store',
    type=str,
    dest='iac_values',
    required=False,
    default='/tmp/event_resources-parameters.json'
)

args = parser.parse_args()
DEBUG = args.verbose

logger = logging.getLogger('cumulus_tunnel_build_and_deploy')
logger.setLevel(logging.INFO)
if DEBUG is True:
    logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
if DEBUG is True:
    ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


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


class AwsCloudServiceProvider(CloudServiceProviderBase):

    def __init__(self, args):
        logger.info('Target AWS')
        self.cloud_formation_strategy = 'CREATE'
        super().__init__(args)

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
                    if stack_summary['StackName'] not in stack_names:
                        stack_names.append(stack_summary['StackName'])
        return stack_names

    def validate_args(self):
        logger.info('Validating values...')
        if os.path.exists(self.args.iac_values) is False:
            raise Exception('Values in JSON parameter file "{}" NOT FOUND. Please create this file or supply another file.'.format(self.args.iac_values))
        logger.info('Using CloudFormation parameters file {}'.format(self.args.iac_values))
        logger.info('Validating basic AWS S3 access...')
        self.upload_artifact(
            source_file='cloud_iac/aws/ec2_setup_scripts/cumulus-tunnel-setup.sh',
            destination={
                'bucket_name': self.args.artifact_location,
                'key': 'cumulus-tunnel-setup.sh',
            }
        )
        logger.info('Artifact upload to S3 works!')
        logger.info('Checking if CloudFormation template "cumulus-tunnel-event-resources" already exists')
        current_cloudformation_stacks = self._list_cloudformation_stacks()
        logger.debug('Current CloudFormation stacks: {}'.format(json.dumps(current_cloudformation_stacks, default=str)))
        if 'cumulus-tunnel-event-resources' in current_cloudformation_stacks:
            self.cloud_formation_strategy = 'CHANGE_SET'
        logger.info('CloudFormation strategy: {}'.format(self.cloud_formation_strategy))

    def build(self):
        self._prep_cloud_serverless_functions()

    def _prep_cloud_serverless_functions(self):
        success = True
        artifacts_to_copy = dict()
        try:
            script_output = run_shell_script(
                "bash",
                "./scripts/package_lambda_function.sh",
                "-f",
                "cloud_iac/aws/lambda_functions/handler_s3_object_created.py",
                "-p",
                "handler_s3_object_created",
            )
            for line in script_output.split('\n'):
                if 'Package File' in line:
                    package_file = line.split(':')[1].strip()
                    file_name = package_file.split(os.sep)[-1]
                    logger.debug('Lambda Package:')
                    logger.debug('\t package_file : {}'.format(package_file))
                    logger.debug('\t file_name    : {}'.format(file_name))
                    artifacts_to_copy[package_file] = dict()
                    artifacts_to_copy[package_file]['bucket_name'] = self.args.artifact_location
                    artifacts_to_copy[package_file]['key'] = file_name
        except RuntimeError as e:
            logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
            success = False
        if success is False:
            raise Exception('Failed to run required lambda prep script "handler_s3_object_created"')
        
        try:
            script_output = run_shell_script(
                "bash",
                "./scripts/package_lambda_function.sh",
                "-f",
                "cloud_iac/aws/lambda_functions/handler_s3_object_delete.py",
                "-p",
                "handler_s3_object_delete",
            )
            for line in script_output.split('\n'):
                if 'Package File' in line:
                    package_file = line.split(':')[1].strip()
                    file_name = package_file.split(os.sep)[-1]
                    logger.debug('Lambda Package:')
                    logger.debug('\t package_file : {}'.format(package_file))
                    logger.debug('\t file_name    : {}'.format(file_name))
                    artifacts_to_copy[package_file] = dict()
                    artifacts_to_copy[package_file]['bucket_name'] = self.args.artifact_location
                    artifacts_to_copy[package_file]['key'] = file_name
        except RuntimeError as e:
            logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
            success = False
        if success is False:
            raise Exception('Failed to run required lambda prep script "handler_s3_object_delete"')
        
        try:
            script_output = run_shell_script(
                "bash",
                "./scripts/package_lambda_function.sh",
                "-f",
                "cloud_iac/aws/lambda_functions/handler_s3_object_expired.py",
                "-p",
                "handler_s3_object_expired",
            )
            for line in script_output.split('\n'):
                if 'Package File' in line:
                    package_file = line.split(':')[1].strip()
                    file_name = package_file.split(os.sep)[-1]
                    logger.debug('Lambda Package:')
                    logger.debug('\t package_file : {}'.format(package_file))
                    logger.debug('\t file_name    : {}'.format(file_name))
                    artifacts_to_copy[package_file] = dict()
                    artifacts_to_copy[package_file]['bucket_name'] = self.args.artifact_location
                    artifacts_to_copy[package_file]['key'] = file_name
        except RuntimeError as e:
            logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
            success = False
        if success is False:
            raise Exception('Failed to run required lambda prep script "handler_s3_object_expired"')
        
        for source_file, destination in artifacts_to_copy.items():
            self.upload_artifact(source_file=source_file, destination=destination)

    def upload_artifact(self, source_file: str, destination: dict):
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        s3 = session.client('s3')
        s3.upload_file(source_file, destination['bucket_name'], destination['key'])
        logger.info('Uploaded file {} to s3://{}/{}'.format(source_file, destination['bucket_name'], destination['key']))


SUPPORTED_CLOUD_SERVICE_PROVIDERS = {
    'aws': AwsCloudServiceProvider
}


def main():
    if args.target_cloud_sp in SUPPORTED_CLOUD_SERVICE_PROVIDERS:
        sp_class: CloudServiceProviderBase
        sp_class = SUPPORTED_CLOUD_SERVICE_PROVIDERS[args.target_cloud_sp]
        sp_class_instance: CloudServiceProviderBase
        sp_class_instance = sp_class(args=args)
        logger.info('Building packages and preparing artifacts')
        sp_class_instance.build()
    else:
        logger.error(
            'Cloud Service Provider "{}" not yet implemented or supported. Supported options: {}'.format(
                args.target_cloud_sp,
                ", ".join(list(SUPPORTED_CLOUD_SERVICE_PROVIDERS.keys())) 
            )
        )


if __name__ == '__main__':
    main()



