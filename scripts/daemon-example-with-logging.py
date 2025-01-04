import os
import sys
import time
import logging
import logging.handlers

def setup_logger(log_file):
    """Sets up a logger to write to a file."""
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8' # 10MB
    )
    log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    log_handler.setFormatter(log_format)

    logger = logging.getLogger(__name__) # use __name__ to get the module name
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)

    return logger

def daemonize(log_file):
    """Detach a process from the controlling terminal and run it in the background with logging."""

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"fork #1 failed: {e.errno} ({e.strerror})\n")
        sys.exit(1)

    os.chdir("/")
    os.setsid()
    os.umask(0)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"fork #2 failed: {e.errno} ({e.strerror})\n")
        sys.exit(1)

    # Setup logger AFTER forking
    logger = setup_logger(log_file)

    # Redirect stdout and stderr to the log file
    sys.stdout.flush()
    sys.stderr.flush()

    # Duplicate file descriptor of the log file handler to stdout and stderr
    so = open(log_file, 'a+')
    se = open(log_file, 'a+')

    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

    logger.info("Daemon process started.")

    # Actual daemon code starts here
    while True:
        logger.info("Daemon is running...")
        print("This will be logged") # This will now go to the log file
        print("This will also be logged", file=sys.stderr) # This will also go to the log file as an error
        try:
            1/0
        except ZeroDivisionError as e:
            logger.exception("A ZeroDivisionError occurred:") # This will log the error with traceback
        time.sleep(5)

if __name__ == "__main__":
    log_file = "/tmp/my_daemon.log"
    if len(sys.argv) > 1 and sys.argv[1] == "daemon":
        daemonize(log_file)
    else:
        print("Starting program. Use 'python script.py daemon' to run as a daemon.")
        print("This will be printed to the console")
        time.sleep(10)
        print("Program finished")
