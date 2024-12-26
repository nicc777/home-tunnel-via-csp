#!/usr/bin/env bash

echo "MAIN SETUP START"

echo "SQS Queue URL set to ${SQS_URL}"

apt install -y nginx net-tools socat python3 python3-venv python3-boto3 python3-flask python3-fastapi
sleep 5
systemctl stop nginx
rm -vf /etc/nginx/sites-enabled/default
aws s3 cp s3://nicc777-artifacts-eu-central-1/etc/nginx/sites-enabled/admin /etc/nginx/sites-enabled/admin 
aws s3 cp s3://nicc777-artifacts-eu-central-1/var/www/html/index.html /var/www/html/index.html
systemctl start nginx

export EXPIRE_TTL=`date -u -d "${SERVER_TTL} hours" +%s`

cat <<EOF >> /tmp/stack_data_for_db
{
    "RecordKey": {
        "S": "relay-server-stack"
    },
    "RecordTtl": {
        "N": "${EXPIRE_TTL}"
    },
    "RecordValue": {
        "S": "{\"StackName\": \"$STACK_NAME\"}"
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

