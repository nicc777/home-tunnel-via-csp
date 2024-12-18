#!/usr/bin/env bash

echo "MAIN SETUP START"

echo "SQS Queue URL set to ${SQS_URL}"

apt install nginx
sleep 5
systemctl stop nginx
rm -vf /etc/nginx/sites-enabled/default
aws s3 cp s3://nicc777-artifacts-eu-central-1/etc/nginx/sites-enabled/admin /etc/nginx/sites-enabled/admin 
aws s3 cp s3://nicc777-artifacts-eu-central-1/var/www/html/index.html /var/www/html/index.html
systemctl start nginx

echo "MAIN SETUP DONE"

