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
    '--refresh_running_vm',
    help='Enables DEBUG logging',
    action='store_true',
    default=False,
    required=False,
    dest='refresh_running_vm'
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


class AwsCloudServiceProvider(CloudServiceProviderBase):

    def __init__(self, args):
        logger.info('Target AWS')
        self.cloud_formation_strategy = 'CREATE'
        self.stack_outputs = list()
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
        self.upload_artifact(
            source_file=self.args.extra_vm_setup,
            destination={
                'bucket_name': self.args.artifact_location,
                'key': 'additional-setup.sh',
            }
        )
        logger.info('Uploading the CloudFormation template...')
        self.upload_artifact(
            source_file='cloud_iac/aws/cloudformation/tunnel_resources.yaml',
            destination={
                'bucket_name': self.args.artifact_location,
                'key': 'tunnel_resources.yaml',
            }
        )

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
        logger.info('\t Sleeping for {} seconds'.format(sleep_interval_seconds))
        time.sleep(sleep_interval_seconds)
        self._wait_for_change_set_status_complete(
            change_set_id=change_set_id,
            next_token=next_token,
            try_count=counter,
            max_tries=max_tries,
            sleep_interval_seconds=sleep_interval_seconds
        )

    def _create_cloudformation_new_stack(self):
        logger.info('Attempting to create a new CloudFormation Stack')
        template_url = 'https://{}.s3.{}.amazonaws.com/tunnel_resources.yaml'.format(
            self.args.artifact_location,
            self.args.csp_region
        )
        logger.debug('template_url: {}'.format(template_url))
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        client = session.client('cloudformation')
        response = client.create_stack(
            StackName='cumulus-tunnel-event-resources',
            TemplateURL=template_url,
            Parameters=load_json_file(file='{}'.format(self.args.iac_values)),
            TimeoutInMinutes=60,
            Capabilities=[
                'CAPABILITY_IAM',
                'CAPABILITY_NAMED_IAM'
            ],
            OnFailure='DO_NOTHING'
        )
        logger.debug('response: {}'.format(json.dumps(response, default=str)))

    def _create_cloudformation_change_set(self):
        logger.info('Attempting to create a CloudFormation Change Set')
        template_url = 'https://{}.s3.{}.amazonaws.com/tunnel_resources.yaml'.format(
            self.args.artifact_location,
            self.args.csp_region
        )
        logger.debug('template_url: {}'.format(template_url))
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        client = session.client('cloudformation')
        response = client.create_change_set(
            StackName='cumulus-tunnel-event-resources',
            TemplateURL=template_url,
            Parameters=load_json_file(file='{}'.format(self.args.iac_values)),
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

    def deploy(self):
        if self.cloud_formation_strategy == 'CREATE':
            self._create_cloudformation_new_stack()
        else:
            self._create_cloudformation_change_set()
        self.stack_outputs = self._get_stack_outputs()
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

    def _get_stack_outputs(self, next_token: str=None)->list:
        outputs = list()
        import boto3
        import boto3.session
        session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
        client = session.client('cloudformation')
        response = dict()
        if next_token is not None:
            response = client.describe_stacks(
                StackName='cumulus-tunnel-event-resources',
                NextToken=next_token
            )
        else:
            response = client.describe_stacks(StackName='cumulus-tunnel-event-resources')
        if 'NextToken' in response:
            data = self._get_stack_outputs(next_token=response['NextToken'])
            outputs += data
        if 'Stacks' in response:
            for stack in response['Stacks']:
                if 'StackName' in stack:
                    if stack['StackName'] == 'cumulus-tunnel-event-resources':
                        if 'Outputs' in stack:
                            outputs = stack['Outputs']
        return outputs

    def refresh_vm(self):
        if self.args.refresh_running_vm is True:
            import boto3
            import boto3.session
            session = boto3.session.Session(profile_name=self.args.csp_profile, region_name=self.args.csp_region)
            client = session.client('autoscaling')


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



