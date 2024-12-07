import argparse

parser = argparse.ArgumentParser(
    prog='cumulus_tunnel_agent',
    description='Agent for cumulus-tunnel',
    epilog='Use at your own risk!'
)

class RuntimeOptions:

    def __init__(self):
        self.exit_after_start = False
        self.debug = False
        self.update_interval_seconds = 86400


runtime_options = RuntimeOptions()

parser.add_argument(
    '-v',
    '--verbose',
    action='store_true',
    default=False
)
parser.add_argument(
    '--update-interval-seconds',
    action='store',
    dest='update_interval_seconds',
    default='3600',
    type=int
)

args = parser.parse_args()

runtime_options.debug = args.verbose
runtime_options.update_interval_seconds = int(args.update_interval_seconds)




