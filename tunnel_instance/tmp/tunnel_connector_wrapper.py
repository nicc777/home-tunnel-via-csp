"""
Initial example SSH usage:

    ssh -t -p 2022 -R 0.0.0.0:8080:127.0.0.1:8999           \
        rtu@$INSTANCE_IP_ADDR                               \
        /usr/bin/python3 /tmp/tunnel_connector_wrapper.py

This will create a pseudo-terminal so that the local terminal can receive
STDOUT etc. as well as properly kill the remote script when CTRL+C is pressed.

Later additional arguments will be added to this script to record status info
in the DynamoDB table for this relay.
"""

import time


def main():
    while True:
        print('Contemplating all things')

        """
        In the future, the sleep time will be HALF that of the TTL in DynamoDB.

        That means the status can be continuously refreshed. When the tunnel is
        closed, this script will exit and the DynamoDB status fields will also
        be deleted soon after the TTL is reached.

        This way, the status can be kept fairly up to date.

        Another alternative is to keep a short sleep time, but count the number
        of iterations and only update the status in DynamoDB just before TTL is
        reached.
        """
        time.sleep(7.0)

if __name__ == '__main__':
    main()


