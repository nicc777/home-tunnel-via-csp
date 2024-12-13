# Prep

Create a Python virtual environment and install requirements:

```shell
python3 -m venv venv

. venv/bin/activate

pip3 install --upgrade -r requirements.txt
```

# General notes

## Agent

This is the app that must be installed on each client that wishes to access the private host through the tunnel.

It will determine the NAT IP address (public IP address) of the client and push that to the cloud, where the IP address will be added to the firewall rules for access.

Additional IP addresses can be added to accommodate systems where the agent can not be installed, for example a mobile phone or tablet.

The files created in the cloud will have a limited life span (default 1 day) after which the files will be deleted. When the files are deleted, the firewall rules are deleted as well, via a Lambda trigger.

# CloudFormation

Start by preparing the AWS Lambda functions (packaging):

```shell
sh ./scripts/package_lambda_function.sh -f cloud_iac/aws/lambda_functions/handler_s3_object_created.py -p handler_s3_object_created

sh ./scripts/package_lambda_function.sh -f cloud_iac/aws/lambda_functions/handler_s3_object_delete.py -p handler_s3_object_delete

sh ./scripts/package_lambda_function.sh -f cloud_iac/aws/lambda_functions/handler_s3_object_expired.py -p handler_s3_object_expired

export ARTIFACT_BUCKET=...
```

Upload the produced ZIP files to an S3 bucket created in the same region as where you want to deploy the CloudFormation template.

You will need the ZIP file path in the output from each of the scripts above to create the appropriate parameter values.

Next, copy the setup scripts that will run each time the virtual machine creating the tunnels will start-up:

```shell
aws s3 cp cloud_iac/aws/ec2_setup_scripts/cumulus-tunnel-setup.sh s3://$ARTIFACT_BUCKET/cumulus-tunnel-setup.sh

aws s3 cp cloud_iac/aws/ec2_setup_scripts/additional-setup.sh s3://$ARTIFACT_BUCKET/additional-setup.sh
```

> [!NOTE]  
> Use the `cloud_iac/aws/ec2_setup_scripts/additional-setup.sh` to add any custom stuff you need to set-up.

Create the S3, SNS and Lambda resources:

```shell
# Create the parameters for the template 
# ADD YOUR OWN VALUES...
rm -vf /tmp/event_resources-parameters.json
cat <<EOF >> /tmp/event_resources-parameters.json
[
    {
        "ParameterKey": "CumulusTunnelBucketNameParam",
        "ParameterValue": "..."
    },
    {
        "ParameterKey": "ArtifactBucketNameParam",
        "ParameterValue": "..."
    },
    {
        "ParameterKey": "LambdaFunctionCreatedS3KeyParam",
        "ParameterValue": "..."
    },
    {
        "ParameterKey": "LambdaFunctionDeletedS3KeyParam",
        "ParameterValue": "..."
    },
    {
        "ParameterKey": "LambdaFunctionExpiredS3KeyParam",
        "ParameterValue": "..."
    },
    {
        "ParameterKey": "VpcId1Param",
        "ParameterValue": "..."
    },
    {
        "ParameterKey": "VpcCidrParam",
        "ParameterValue": "..."
    },
    {
        "ParameterKey": "SubnetId1Param",
        "ParameterValue": "..."
    },
    {
        "ParameterKey": "SubnetId2Param",
        "ParameterValue": "..."
    },
    {
        "ParameterKey": "SubnetId3Param",
        "ParameterValue": "..."
    },
    {
        "ParameterKey": "DebugParam",
        "ParameterValue": "1"
    },
    {
        "ParameterKey": "CumulusTunnelAmiIdParam",
        "ParameterValue": "..."
    }
]
EOF

PARAMETERS_FILE="file:///tmp/event_resources-parameters.json" && \
TEMPLATE_BODY="file://$PWD/cloud_iac/aws/cloudformation/tunnel_resources.yaml" && \
aws cloudformation create-stack \
--stack-name cumulus-tunnel-event-resources \
--template-body $TEMPLATE_BODY \
--parameters $PARAMETERS_FILE \
--capabilities CAPABILITY_NAMED_IAM \
--profile $PROFILE \
--region $REGION
```
