"""
Proof of concept to move a Python script to the background, detached from the
console.

This example was generated by Gemini AI on 2025-01-04 around 13:30 with the 
following prompt:

    When I run a python3 program, how do I detach it from the current linux
    console or terminal from within the python program? I want to let the
    program run in the background and give back control of the terminal to the
    user, but without using any Linux specific commands for example "nohup". 
"""

import os
import sys
import time

def daemonize():
    """Detach a process from the controlling terminal and run it in the background."""

    try:
        pid = os.fork()
        if pid > 0:
            # Exit first parent
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"fork #1 failed: {e.errno} ({e.strerror})\n")
        sys.exit(1)

    # Decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)

    # Do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # Exit from second parent
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"fork #2 failed: {e.errno} ({e.strerror})\n")
        sys.exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = open(os.devnull, 'r')
    so = open(os.devnull, 'a+')
    se = open(os.devnull, 'a+')

    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

    # Actual daemon code starts here
    # ... your background task ...
    print("Daemon process started.") # this will be written to /dev/null

    while True:
      # Do some work in the background
      print("Daemon is running")
      time.sleep(5)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "daemon":
        daemonize()
    else:
        print("Starting program. Use 'python script.py daemon' to run as a daemon.")
        # Your normal program code if not running as daemon
        time.sleep(10)
        print("Program finished")
