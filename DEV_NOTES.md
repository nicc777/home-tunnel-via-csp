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

rm -vf $HOME/.cumulus_tunnel_state.sqlite

python3 scripts/get_api_tokens.py

cp -vf /tmp/cumulus_tunnel_api.json $HOME/.cumulus_tunnel_api.json

cp -vf /tmp/cumulus_tunnel_standard_api_parameters.json $HOME/.cumulus_tunnel_standard_api_parameters.json

# Name the relay server
export RELAY_SERVER_NAME="test-relay"

# Start a test relay server
export S=$PWD && cd client/relay-server-registration/src && \
python3 -m relay_server_registration.main                   \
-v --run-once --identifier=$RELAY_SERVER_NAME               \
--cloud-profile-name=$AWS_PROFILE && cd $S

# Get the latest password for SSH:
PAGER="" aws secretsmanager get-secret-value                          \
--region $AWS_REGION --profile $AWS_PROFILE                           \
--secret-id "cumulus-tunnel-api-resources-stack-tunnel-http-password" \
--query SecretString --output text | jq -r ".password"

# --OR-- to save the password in an environment variable:
export RELAY_PW=$(PAGER="" aws secretsmanager get-secret-value --region $AWS_REGION --profile $AWS_PROFILE --secret-id "cumulus-tunnel-api-resources-stack-tunnel-http-password" --query SecretString --output text | jq -r ".password")

# Get the instance ID:
export INSTANCE_ID=`PAGER="" aws ec2 describe-instances --filters "Name=tag:Name,Values=${RELAY_SERVER_NAME}-admin" --query 'Reservations[*].Instances[*].InstanceId' --output text --region $AWS_REGION --profile $AWS_PROFILE`

# Get the Instance IP Address
export INSTANCE_IP_ADDR=$(PAGER="" aws ec2 describe-instances --filters "Name=tag:Name,Values=${RELAY_SERVER_NAME}-admin" "Name=instance-state-name,Values=running" --output json --region $AWS_REGION --profile $AWS_PROFILE | jq -r '.Reservations[].Instances[].PublicIpAddress')

# Setup a simple test local web server
mkdir /tmp/simple-static
echo "<html><head><title>Simple Test</head></title><body><h3>It Works</h3></body></html>" > /tmp/simple-static/index.html
podman run --name static-web-test -v /tmp/simple-static:/usr/share/nginx/html:ro -d -p 8999:80 docker.io/nginx:latest
curl http://localhost:8999

# Register the client that will access the relay
export S=$PWD && cd client/client-registration/src && \
python3 -m client_registration.main                   \
-v --run-once --relay-id=$RELAY_SERVER_NAME && cd $S

# SSH to the newly launched instance to test:
ssh -p 2022 -R 0.0.0.0:8080:127.0.0.1:8999  rtu@$INSTANCE_IP_ADDR

# In another terminal, test:
curl https://${RELAY_SERVER_NAME}-admin.${PARAM_DOMAIN_NAME}/

curl https://${RELAY_SERVER_NAME}-admin.${PARAM_DOMAIN_NAME}:8081/
```

# Various Notes

Python path on the relay server: `/usr/bin/python3`

# Configurations (concepts)

In the future I want to move away from all the command line parameters and rather use config files only.

These examples include some future feature evolution which is not yet supported.

## Build Server

This is the server/system from where the infrastructure is provisioned:

```yaml
---
CloudProviders:
  Provider:
  - Name: my-aws        # Supported cloud provider. Only AWS for now.
    Context:            # Some providers may only be for either "relay" or "domain" configuration    
    - relay             
    - domain
    Type: aws
    Profile: default    # Assuming all cloud provider will had some concept of a profile and region
    Region: eu-central-1
    TargetApiConfiguration: # For API config distribution. Systems not on the network or not reachable at the provisioning time will be skipped
      LocalPath: /tmp/.cumulus_tunnel_api.json
      Distribution:
        ResourceServers:
        - Hostname: my-server
          Username: my-user
          SshPrivateKey: /home/user/.ssh/some-key.pem
          TargetPath: /home/user/.cumulus_tunnel_api.json
        Clients:
        - Hostname: my-laptop
          Username: my-user
          SshPrivateKey: /home/user/.ssh/some-key.pem
          TargetPath: /home/user/.cumulus_tunnel_api.json
    Configuration:      
    - Name: VPC_ID
      Value: xxx
      EnvOverride: PARAM_VPC_ID
    - Name: VPC_CIDR
      Value: xxx
      EnvOverride: PARAM_VPC_CIDR
    - Name: SUBNET_1_ID
      Value: xxx
      EnvOverride: PARAM_SUBNET_1_ID
    - Name: SUBNET_2_ID
      Value: xxx
      EnvOverride: PARAM_SUBNET_2_ID
    - Name: SUBNET_3_ID
      Value: xxx
      EnvOverride: PARAM_SUBNET_3_ID
    - Name: AMI
      Value: xxx
      EnvOverride: PARAM_AMI
---
Domains:                # One or more domain zones can be defined here
  Provider:
  - DomainName: example.tld
    Provider:
      Name: my-aws
    Config:             # Depends on the Domain Registrar - only AWS Route 53 supported right now
    - ParameterName: ZoneId
      ParameterValue: ABC123
    - ParameterName: AwsCertificateManagerCertificateARN
      ParameterValue: arn:aws:acm:eu-central-1:123456789012:certificate/aaaaaaaa-aaaa-aaaa-aaaa-xxxxxxxxxxxx
```

## Relay Server(s) Config

Something like this:

```yaml
---
Domains:                # One or more domain zones can be defined here
  Provider:
  - DomainName: example.tld
    Config:             # Depends on the Domain Registrar - only AWS Route 53 supported right now
    - ParameterName: ZoneId
      ParameterValue: ABC123
    - ParameterName: AwsCertificateManagerCertificateARN
      ParameterValue: arn:aws:acm:eu-central-1:123456789012:certificate/aaaaaaaa-aaaa-aaaa-aaaa-xxxxxxxxxxxx
---  
RelayServer:
  Name: test-relay              # Identifier
  HttpProxy:                    # Creates a Load Balancer that will set-up a connection via the relay-server Nginx instance
    VirtualDomains:             # Nginx configurations
    - DomainName: example.tld
      Port: 80
      # At some future point, TLS and authentication configuration will also be added
      IpProtocols:
      - Type: IPv4
        Interface: "0.0.0.0"
      - Type: IPv6:
        Interface: [::]
      Headers:                  # Adds nginx "proxy_set_header" entries
      - Name: Host
        Value: "$host"
      - Name: X-Real-IP
        Value: "$remote_addr"
      ProxyPass:
        Host: localhost
        Port: 8080              # When building a tunnel from the resource server, this is the port to target on the relay server
        Protocol: http          # http|https
      Ingress:                  # For AWS, this is the LoadBalancer configuration
        Enable: true            # For AWS, this will provision a Target Group targeting this port and a listener bound to the DNS name
        DnsRecordNames:         # For AWS, this will provision a listener with matches for any of the supplied record names, and it will also add the DNS records. Requires the "Domains" configuration section.
        - name1                 # Traffic on name1.example.tld will be routed to the Load Balancer and forwarded to the target group that targets port 80 of the relay server
        - name2
  ApiConfig:                    # Where the API configuration is stored.
    Path: /home/user/.cumulus_tunnel_api.json
  CustomSetupScript:            # Will be included in the setup process, after the main setup script has run
    Path: /dev/null
  DomainConfigurations:         # Requires a "Domains" configuration section in the YAML file
  - DomainName: example.tld
    Records:
    - RecordName: ssh-test-relay  # This record will point to the public IP address of the Relay Server.
```

## Client Config

Something like this:

```yaml
---
Client:
  Name: my-laptop
  TargetRelays:
  - Name: test-relay
    EnableRelayAccess: true
    EnableHttpProxyAccess: true
  Mode: run-once|interval   # Default: "interval" - will reconcile every "IntervalSeconds"
  IntervalSeconds: 3600     # If mode is interval, the sleep time can be adjusted here...
  ApiConfig:                # Where the API configuration is stored. Default is $HOME/.cumulus_tunnel_api.json
    Path: /home/user/.cumulus_tunnel_api.json
  SkipNat: false            # If "true", won't attempt to automatically add NAT addresses
  SkipDefaultRelayPorts: false        # By default, ports to the relay will be added (2022)
  SkipDefaultLoadBalancerPorts: false # By default, ports to the load balancer will be added (80, 443, 8081)
  IpAddresses:              # When "SkipNat" is "true", at least some IP addresses MUST be added
    Relay:                  # If "TargetRelays.[].EnableRelayAccess" is "true"
      IPv4:
      - 123.123.123.123/32  # Additional IP addresses to add to the security groups / firewall for the relay-server
      IPv6:
      - string-with-ipv6-address
    HttpProxy:              # If "TargetRelays.[].EnableHttpProxyAccess" is "true"
      IPv4:
      - 123.123.123.123/32  # Additional IP addresses to add to the security groups / firewall for the load balancer to the HTTP proxy
      IPv6:
      - string-with-ipv6-address
```

