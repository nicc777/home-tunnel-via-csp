#!/usr/bin/env bash

echo "MAIN SETUP START"

echo "SQS Queue URL set to ${SQS_URL}"

apt install -y nginx net-tools socat python3 python3-venv python3-boto3 python3-flask python3-fastapi
sleep 5

# NGINX
systemctl stop nginx
rm -vf /etc/nginx/sites-enabled/default
aws s3 cp s3://$ARTIFACT_BUCKET_NAME/etc/nginx/sites-enabled/admin /etc/nginx/sites-enabled/admin
aws s3 cp s3://$ARTIFACT_BUCKET_NAME/var/www/html/index.html /var/www/html/index.html
systemctl start nginx

# SSH
mkdir -p /etc/systemd/system/ssh.socket.d/
aws s3 cp s3://$ARTIFACT_BUCKET_NAME/etc/ssh/sshd_config /etc/ssh/sshd_config
aws s3 cp s3://$ARTIFACT_BUCKET_NAME/etc/systemd/system/ssh.socket.d/override.conf /etc/systemd/system/ssh.socket.d/override.conf
systemctl daemon-reload
systemctl restart ssh.socket
systemctl restart ssh

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
SECURITY_GROUP_IDS=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/security-groups)
INSTANCE_ID_RECORD_KEY="relay-server:instance-id:${MANAGEMENT_DOMAIN}"

echo "Instance ID: $INSTANCE_ID"
echo "Security Group IDs: $SECURITY_GROUP_IDS"

cat <<EOF > /tmp/relay_instance_id
{
    "RecordKey": {
        "S": "${INSTANCE_ID_RECORD_KEY}"
    },
    "RecordTtl": {
        "N": "${EXPIRE_TTL}"
    },
    "RecordValue": {
        "S": "[{\"parameter_name\": \"RecordKey\", \"parameter_type\": \"str\", \"parameter_value\": \"$INSTANCE_ID_RECORD_KEY\"},{\"parameter_name\": \"RecordTtl\", \"parameter_type\": \"str\", \"parameter_value\": \"$EXPIRE_TTL\"}]"
    },
    "CommandOnTtl": {
        "S": "delete_dynamodb_record"
    },
    "RecordOrigin": {
        "S": "resource"
    }
}
EOF
aws dynamodb put-item --table-name cumulus-tunnel  --item file:///tmp/relay_instance_id


aws ec2 describe-instances \
--instance-ids $INSTANCE_ID \
--query 'Reservations[*].Instances[*].SecurityGroups[*].GroupId' \
--output json | jq -r '.[]' | jq -r '.[] | @csv' | sed 's/"//g'

IFS=',' read -r -a array <<< "$my_list"

for group in "${array[@]}"; do
  echo "Security Group ID: $group"
  RECORD_KEY="relay-server:security-groups:${MANAGEMENT_DOMAIN}:${group}"
cat <<EOF > /tmp/relay_instance_security_group
{
    "RecordKey": {
        "S": "${RECORD_KEY}"
    },
    "RecordTtl": {
        "N": "${EXPIRE_TTL}"
    },
    "RecordValue": {
        "S": "[{\"parameter_name\": \"RecordKey\", \"parameter_type\": \"str\", \"parameter_value\": \"$RECORD_KEY\"},{\"parameter_name\": \"RecordTtl\", \"parameter_type\": \"str\", \"parameter_value\": \"$EXPIRE_TTL\"}]"
    },
    "CommandOnTtl": {
        "S": "delete_dynamodb_record"
    },
    "RecordOrigin": {
        "S": "resource"
    }
}
EOF
    aws dynamodb put-item --table-name cumulus-tunnel  --item file:///tmp/relay_instance_security_group
done

### DONE
echo "MAIN SETUP DONE"

nohup socat TCP-LISTEN:22,fork,reuseaddr TCP:localhost:2222

