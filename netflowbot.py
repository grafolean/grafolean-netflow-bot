import argparse
import gzip
import json
import logging
import os
import sys
import time
from collections import defaultdict

from colors import color
import dotenv
import redis

from grafoleancollector import Collector


logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "base"))


REDIS_HOST = os.environ.get('REDIS_HOST', '127.0.0.1')
r = redis.Redis(host=REDIS_HOST)


class NetFlowBot(Collector):
    pass


def wait_for_grafolean(backend_url):
    while True:
        url = '{}/status/info'.format(backend_url)
        log.info("Checking Grafolean status...")
        try:
            r = requests.get(url)
            r.raise_for_status()
            status_info = r.json()
            if status_info['db_migration_needed'] == False and status_info['user_exists'] == True:
                log.info("Grafolean backend is ready.")
                return
        except:
            pass
        log.info("Grafolean backend not available / initialized yet, waiting.")
        time.sleep(10)


if __name__ == "__main__":
    dotenv.load_dotenv()

    backend_url = os.environ.get('BACKEND_URL')
    jobs_refresh_interval = int(os.environ.get('JOBS_REFRESH_INTERVAL', 120))

    if not backend_url:
        raise Exception("Please specify BACKEND_URL env var.")

    wait_for_grafolean(backend_url)

    bot_token = os.environ.get('BOT_TOKEN')
    if not bot_token:
        # bot token can also be specified via contents of a file:
        bot_token_from_file = os.environ.get('BOT_TOKEN_FROM_FILE')
        if bot_token_from_file:
            with open(bot_token_from_file, 'rt') as f:
                bot_token = f.read()
    if not bot_token:
        raise Exception("Please specify BOT_TOKEN / BOT_TOKEN_FROM_FILE env var.")

    b = NetFlowBot(backend_url, bot_token, jobs_refresh_interval)
    b.execute()
