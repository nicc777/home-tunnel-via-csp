#!/usr/bin/env python3

import os
import sys
import logging
import argparse
import traceback
import subprocess


parser = argparse.ArgumentParser(
    prog='cumulus_tunnel_agent',
    description='Agent for cumulus-tunnel',
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
        pass

    def validate_args(self):
        raise Exception('Must be implemented by CSP class')

    def build(self):
        raise Exception('Must be implemented by CSP class')
    
    def _prep_lambda_functions(self):
        """
            sh ./scripts/package_lambda_function.sh -f cloud_iac/aws/lambda_functions/handler_s3_object_created.py -p handler_s3_object_created
            sh ./scripts/package_lambda_function.sh -f cloud_iac/aws/lambda_functions/handler_s3_object_delete.py -p handler_s3_object_delete
            sh ./scripts/package_lambda_function.sh -f cloud_iac/aws/lambda_functions/handler_s3_object_expired.py -p handler_s3_object_expired
        """
        success = True
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
        except RuntimeError as e:
            logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
            success = False
        if success is False:
            raise Exception('Failed to run required lambda prep script.')


class AwsCloudServiceProvider(CloudServiceProviderBase):

    def __init__(self, args):
        logger.info('Target AWS')
        super().__init__(args)

    def validate_args(self):
        pass

    def build(self):
        self._prep_lambda_functions()


SUPPORTED_CLOUD_SERVICE_PROVIDERS = {
    'aws': AwsCloudServiceProvider
}


def main():
    if args.target_cloud_sp in SUPPORTED_CLOUD_SERVICE_PROVIDERS:
        sp_class: CloudServiceProviderBase
        sp_class = SUPPORTED_CLOUD_SERVICE_PROVIDERS[args.target_cloud_sp]
        sp_class_instance: CloudServiceProviderBase
        sp_class_instance = sp_class(args=args)
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



