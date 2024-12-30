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


export EXPIRE_TTL=`date -u -d "${SERVER_TTL} hours" +%s`

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

# Save the STACK_NAME value for this relay server
aws dynamodb put-item --table-name cumulus-tunnel  --item file:///tmp/stack_data_for_db

echo "MAIN SETUP DONE"

