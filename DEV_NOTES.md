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

```text
-h, --help            show this help message and exit
  -v, --verbose         Enables DEBUG logging
  --cloud TARGET_CLOUD_SP
                        A target cloud environment. Supported options: "aws"
  --artifact_location ARTIFACT_LOCATION
                        A target location to upload artifacts to, for example an S3 bucket name
  --profile CSP_PROFILE
                        The cloud profile to use. Processing is based on the implementations of the selected Cloud Service
                        Provider - refer to documentation for more information. For AWS, this is simply the AWS profile
                        name.
  --region CSP_REGION   The cloud region to use. Refer to the specific Cloud Service Provider documentation for valid region
                        values.
  --extra_vm_setup EXTRA_VM_SETUP
                        The optional custom setup script to be run when the tunnel VM starts up. Must be a SHELL script, if
                        supplied.
  --param_vpc_id PARAM_VPC_ID
                        The VPC ID to be used. This is where the relay server will be deployed in.
  --param_vpc_cidr PARAM_VPC_CIDR
                        The CIDR address of the VPC
  --param_public_subnet_1_id PARAM_PUBLIC_SUBNET_ID_1
                        ID of public Subnet 1 in the VPC
  --param_public_subnet_2_id PARAM_PUBLIC_SUBNET_ID_2
                        ID of public Subnet 2 in the VPC
  --param_public_subnet_3_id PARAM_PUBLIC_SUBNET_3D_1
                        ID of public Subnet 3 in the VPC
  --param_relay_vm_identifier PARAM_RELAY_VM_IDENTIFIER
                        The VM image ID. For AWS this must be an AMI to use
  --param_base_domain_name PARAM_BASE_DOMAIN_NAME
                        The domain name for creating records. You MUST own and control this domain.
  --param_aws_route53_zone_id PARAM_AWS_ROUTE53_ZONE_ID
                        The AWS Route 53 Zone ID. For now, this parameter is required, but this may change in the future
                        when more cloud providers are supported.
  --param_aws_acm_arn PARAM_AWS_ACM_ARN
                        The AWS ACM Certificate ARN for the selected domain (typically a wild-card certificate). For now,
                        this parameter is required, but this may change in the future when more cloud providers are
                        supported.
```

Prepare environment variables:

```shell
export ARTIFACT_BUCKET=...
export AWS_PROFILE=...
export AWS_REGION=...
export PARAM_VPC_ID=...
export PARAM_VPC_CIDR=...
export PARAM_SUBNET_1_ID=...
export PARAM_SUBNET_2_ID=...
export PARAM_SUBNET_3_ID=...
export PARAM_AMI=...
export PARAM_DOMAIN_NAME-...
export PARAM_ROUTE53_ZONE_ID=...
export PARAM_ACM_ARN=...
```

Run the deployment:

```shell
python3 build_and_deploy.py                         \
--artifact_location=$ARTIFACT_BUCKET                \
--profile=$AWS_PROFILE                              \
--region=$AWS_REGION                                \
--param_vpc_id=$PARAM_VPC_ID                        \
--param_vpc_cidr=$PARAM_VPC_CIDR                    \
--param_public_subnet_1_id=$PARAM_SUBNET_1_ID       \
--param_public_subnet_2_id=$PARAM_SUBNET_2_ID       \
--param_public_subnet_3_id=$PARAM_SUBNET_3_ID       \
--param_relay_vm_identifier=$PARAM_AMI              \
--param_base_domain_name=$PARAM_DOMAIN_NAME         \
--param_aws_route53_zone_id=$PARAM_ROUTE53_ZONE_ID  \
--param_aws_acm_arn=$PARAM_ACM_ARN

python3 scripts/get_api_tokens.py

cp -vf /tmp/cumulus_tunnel_api.json $HOME/.cumulus_tunnel_api.json

cp -vf /tmp/cumulus_tunnel_standard_api_parameters.json $HOME/.cumulus_tunnel_standard_api_parameters.json

# Name the relay server
export RELAY_SERVER_NAME="test-relay"

# Start a test relay server
rm -vf $HOME/.cumulus_tunnel_state.sqlite &&                  \
export S=$PWD && cd client/commander/src &&                   \
python3 -m cumulus_tunnel_commander.cumulus_tunnel_commander  \
-v --run-once --identifier=$RELAY_SERVER_NAME                 \
--cloud-profile-name=$AWS_PROFILE && cd $S

# Get the latest password for SSH:
PAGER="" aws secretsmanager get-secret-value                          \
--region $AWS_REGION --profile $AWS_PROFILE                           \
--secret-id "cumulus-tunnel-api-resources-stack-tunnel-http-password" \
--query SecretString --output text | jq -r ".password"

# Het the instance ID:
export INSTANCE_ID=`PAGER="" aws ec2 describe-instances --filters "Name=tag:Name,Values=${RELAY_SERVER_NAME}-admin" --query 'Reservations[*].Instances[*].InstanceId' --output text --region $AWS_REGION --profile $AWS_PROFILE`

# Get the Instance IP Address
export INSTANCE_IP_ADDR=`PAGER="" aws ec2 describe-instances --filters "Name=tag:Name,Values=${RELAY_SERVER_NAME}-admin" --output json --region $AWS_REGION --profile $AWS_PROFILE | jq -r '.Reservations[].Instances[].PublicIpAddress'`

# Setup a simple test local web server
mkdir /tmp/simple-static
echo "<html><head><title>Simple Test</head></title><body><h3>It Works</h3></body></html>" > /tmp/simple-static/index.html
podman run --name static-web-test -v /tmp/simple-static:/usr/share/nginx/html:ro -d -p 8999:80 docker.io/nginx:latest
curl http://localhost:8999

# SSH to the newly launched instance to test:
ssh -p 2022 -R 0.0.0.0:8999:8999  rtu@$INSTANCE_IP_ADDR

# NOTE - for now I still have to add manually my IP address to the SG....

# In another terminal, test:
curl http://$INSTANCE_IP_ADDR:8999
```

# API Command Structures

## General Format

Schema:

```json
{
  "command": "string",
  "command_parameters": [
    {
      "parameter_name": "string",
      "parameter_type": "string",
      "parameter_value": "string"
    }
  ]
}
```

## Resource Server Commands

### Create a new Relay

Example:

```json
{
  "command": "create_relay_server",
  "command_parameters": [
    {
      "parameter_name": "ArtifactBucketNameParam",
      "parameter_type": "str",
      "parameter_value": "..."
    },
    {
      "parameter_name": "VpcId1Param",
      "parameter_type": "str",
      "parameter_value": "..."
    },
    {
      "parameter_name": "VpcCidrParam",
      "parameter_type": "str",
      "parameter_value": "..."
    },
    {
      "parameter_name": "SubnetId1Param",
      "parameter_type": "str",
      "parameter_value": "..."
    },
    {
      "parameter_name": "SubnetId2Param",
      "parameter_type": "str",
      "parameter_value": "..."
    },
    {
      "parameter_name": "SubnetId3Param",
      "parameter_type": "str",
      "parameter_value": "..."
    },
    {
      "parameter_name": "DebugParam",
      "parameter_type": "str",
      "parameter_value": "..."
    },
    {
      "parameter_name": "CumulusTunnelAmiIdParam",
      "parameter_type": "str",
      "parameter_value": "..."
    },
    {
      "parameter_name": "DefaultRoute53ZoneIdParam",
      "parameter_type": "str",
      "parameter_value": "..."
    },
    {
      "parameter_name": "DefaultRoute53DomainParam",
      "parameter_type": "str",
      "parameter_value": "..."
    },
    {
      "parameter_name": "ManagementDomainRecordParam",
      "parameter_type": "str",
      "parameter_value": "..."
    },
    {
      "parameter_name": "DomainCertificateArnParam",
      "parameter_type": "str",
      "parameter_value": "..."
    },
    {
      "parameter_name": "Ec2InstanceTypeParam",
      "parameter_type": "str",
      "parameter_value": "t4g.nano"
    },
    {
      "parameter_name": "RelayServerTtlHoursParam",
      "parameter_type": "str",
      "parameter_value": "12"
    }
  ]
}
```

### Delete an Existing Relay

Example:

```json
{
  "command": "delete_relay_server_stack",
  "command_parameters": [
    {
      "parameter_name": "stack_name",
      "parameter_type": "str",
      "parameter_value": "...."
    }
  ]
}
```

## Agent Commands

### Register a new agent

Example:

```json
{
  "command": "string",
  "command_parameters": [
    {
      "parameter_name": "string",
      "parameter_type": "string",
      "parameter_value": "string"
    }
  ]
}
```

