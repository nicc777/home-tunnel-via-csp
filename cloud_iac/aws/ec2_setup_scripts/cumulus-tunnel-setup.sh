#!/usr/bin/env bash

echo "MAIN SETUP START"

echo "SQS Queue URL set to ${SQS_URL}"

apt install -y nginx net-tools socat python3 python3-venv python3-boto3 python3-flask python3-fastapi
sleep 5

# NGINX
systemctl stop nginx
rm -vf /etc/nginx/sites-enabled/default
aws s3 cp s3://$ARTIFACT_BUCKET_NAME/etc/nginx/sites-enabled/admin /etc/nginx/sites-enabled/admin
aws s3 cp s3://$ARTIFACT_BUCKET_NAME/etc/nginx/nginx.conf /etc/nginx/nginx.conf
aws s3 cp s3://$ARTIFACT_BUCKET_NAME/var/www/html/index.html /var/www/html/index.html
sed -i -e "s/__DOMAIN__/${DOMAIN_NAME}/g" /etc/nginx/sites-enabled/admin
systemctl start nginx

# SSH
mkdir -p /etc/systemd/system/ssh.socket.d/
aws s3 cp s3://$ARTIFACT_BUCKET_NAME/etc/ssh/sshd_config /etc/ssh/sshd_config
aws s3 cp s3://$ARTIFACT_BUCKET_NAME/etc/systemd/system/ssh.socket.d/override.conf /etc/systemd/system/ssh.socket.d/override.conf
systemctl daemon-reload
systemctl restart ssh.socket
systemctl restart ssh

# Wrapper script:
aws s3 cp s3://$ARTIFACT_BUCKET_NAME/tmp/tunnel_connector_wrapper.py /tmp/tunnel_connector_wrapper.py

# Create tunnel user
export PW=`PAGER="" aws secretsmanager get-secret-value  --secret-id "cumulus-tunnel-api-resources-stack-tunnel-http-password" --query SecretString --output text | jq -r ".password" `
echo dummy | adduser --shell /usr/bin/bash -comment "Relay Tunnel User" --home /home/rtu --quiet rtu
echo "rtu:${PW}" | chpasswd


# Save the STACK_NAME value for this relay server
EXPIRE_TTL=`date -u -d "${SERVER_TTL} hours" +%s`
cat <<EOF > /tmp/stack_data_for_db
{
    "RecordKey": {
        "S": "relay-server-stack"
    },
    "RecordTtl": {
        "N": "${EXPIRE_TTL}"
    },
    "RecordValue": {
        "S": "{\"parameter_name\": \"stack_name\", \"parameter_type\": \"str\", \"parameter_value\": \"$STACK_NAME\"}"
    },
    "CommandOnTtl": {
        "S": "delete_relay_server_stack"
    },
    "RecordOrigin": {
        "S": "resource"
    }
}
EOF
aws dynamodb put-item --table-name cumulus-tunnel  --item file:///tmp/stack_data_for_db


# Persist data about this relay server
END_OF_TIME=32503680000 # At this point, who cares?
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/instance-id)
RELAY_SERVER_ID=$(echo "$MANAGEMENT_DOMAIN" | sed -e "s/-admin//g")
INSTANCE_ID_RECORD_KEY="relay-server:instance-id:${RELAY_SERVER_ID}"
echo "Instance ID: $INSTANCE_ID"
cat <<EOF > /tmp/relay_instance_id
{
    "RecordKey": {
        "S": "${INSTANCE_ID_RECORD_KEY}"
    },
    "RecordTtl": {
        "N": "${EXPIRE_TTL}"
    },
    "RecordValue": {
        "S": "{\"InstanceId\": \"${INSTANCE_ID}\"}"
    },
    "CommandOnTtl": {
        "S": "IGNORE"
    },
    "RecordOrigin": {
        "S": "resource"
    }
}
EOF
aws dynamodb put-item --table-name cumulus-tunnel  --item file:///tmp/relay_instance_id


MAIN_SECURITY_GROUP_NAME="${MANAGEMENT_DOMAIN}-relay-server-sg"
MAIN_SECURITY_GROUP_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=${MAIN_SECURITY_GROUP_NAME}" --query 'SecurityGroups[*].GroupId' --output text)

ALB_SECURITY_GROUP_NAME="${MANAGEMENT_DOMAIN}-alb-sg"
ALB_SECURITY_GROUP_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=${ALB_SECURITY_GROUP_NAME}" --query 'SecurityGroups[*].GroupId' --output text)

RECORD_KEY_MAIN_SG="relay-server:security-group:${RELAY_SERVER_ID}"
cat <<EOF > /tmp/relay_instance_security_groups
{
    "RecordKey": {
        "S": "${RECORD_KEY_MAIN_SG}"
    },
    "RecordTtl": {
        "N": "${EXPIRE_TTL}"
    },
    "RecordValue": {
        "S": "{\"SecurityGroupName\": \"${MAIN_SECURITY_GROUP_NAME}\", \"SecurityGroupId\": \"${MAIN_SECURITY_GROUP_ID}\"}"
    },
    "CommandOnTtl": {
        "S": "IGNORE"
    },
    "RecordOrigin": {
        "S": "resource"
    }
}
EOF
aws dynamodb put-item --table-name cumulus-tunnel  --item file:///tmp/relay_instance_security_groups

RECORD_KEY_ALB_SG="relay-server:alb-security-group:${RELAY_SERVER_ID}"
cat <<EOF > /tmp/alb_security_groups
{
    "RecordKey": {
        "S": "${RECORD_KEY_ALB_SG}"
    },
    "RecordTtl": {
        "N": "${EXPIRE_TTL}"
    },
    "RecordValue": {
        "S": "{\"SecurityGroupName\": \"${ALB_SECURITY_GROUP_NAME}\", \"SecurityGroupId\": \"${ALB_SECURITY_GROUP_ID}\"}"
    },
    "CommandOnTtl": {
        "S": "IGNORE"
    },
    "RecordOrigin": {
        "S": "resource"
    }
}
EOF
aws dynamodb put-item --table-name cumulus-tunnel  --item file:///tmp/alb_security_groups

### DONE
echo "MAIN SETUP DONE"

nohup socat TCP-LISTEN:22,fork,reuseaddr TCP:localhost:2222

