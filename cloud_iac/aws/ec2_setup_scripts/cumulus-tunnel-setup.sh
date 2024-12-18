#!/usr/bin/env bash

echo "MAIN SETUP START"

echo "SQS Queue URL set to ${SQS_URL}"

apt install nginx
systemctl stop nginx
rm -vf /etc/nginx/sites-enabled/default

echo "MAIN SETUP DONE"

