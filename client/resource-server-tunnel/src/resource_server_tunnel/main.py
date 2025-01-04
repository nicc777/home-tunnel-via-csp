import os
import sys
import logging
import time
import json
import socket
import traceback
import copy
from datetime import datetime, timedelta

import requests

from resource_server_tunnel.args import args, command, local_port, remote_port
from resource_server_tunnel.state import StateManagementFunctions


state_functions = StateManagementFunctions(state_file_path=args.state_file)


def main():
    print('Started with command "{}"'.format(command))
    if command == 'create_new_tunnel':
        print('  Remote Port : {}'.format(remote_port))
        print('  Local Port  : {}'.format(local_port))


if __name__ == '__main__':
    main()

