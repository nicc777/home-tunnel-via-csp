
import logging
import logging.handlers
import os
import tempfile


DEBUG = bool(int(os.getenv('DEBUG', '0')))
LOG_LEVEL = logging.INFO
if DEBUG is True:
    LOG_LEVEL = logging.DEBUG


logger = logging.getLogger(os.path.basename(__file__).replace('.py', ''))
for handler in logger.handlers[:]: 
    logger.removeHandler(handler)
logger.setLevel(LOG_LEVEL)
ch = logging.handlers.RotatingFileHandler(
    filename='{}{}XXX'.format(tempfile.gettempdir(), os.sep),
    maxBytes=1024*1024,
    backupCount=10
)
ch.setLevel(LOG_LEVEL)
formatter = logging.Formatter('%(asctime)s %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

