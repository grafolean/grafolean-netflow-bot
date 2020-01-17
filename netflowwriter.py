import argparse
import gzip
import json
import logging
import os
import errno
import sys
import time
from collections import defaultdict
from datetime import datetime

import psycopg2.extras
from colors import color
import redis

from lookup import PROTOCOLS, REDIS_HASH_TRAFFIC_PER_PROTOCOL
from dbutils import migrate_if_needed, db, DB_PREFIX


logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "base"))


REDIS_HOST = os.environ.get('REDIS_HOST', '127.0.0.1')
r = redis.Redis(host=REDIS_HOST)


def process_named_pipe(named_pipe_filename):
    try:
        os.mkfifo(named_pipe_filename)
    except OSError as ex:
        if ex.errno != errno.EEXIST:
            raise

    while True:
        with open(named_pipe_filename, "rb", 0) as fp:
            log.info(f"Opened named pipe {named_pipe_filename}")
            for line in fp:
                if len(line) == 0:
                    log.info("Named pipe closed")
                    break

                log.info(f"Received record: {len(line)} bytes")
                write_record(json.loads(line))


def write_record(j):

    ts = j["ts"]
    client_ip, _ = j["client"]
    version = j["version"]
    flows = j["flows"]
    data = defaultdict(int)
    for flow in flows:
        # aggregation in Redis:
        protocol = flow['PROTOCOL']
        in_bytes = flow['IN_BYTES']

        protocol_str = PROTOCOLS.get(protocol, f'?{protocol}')
        data[protocol_str] += in_bytes

    for k, v in data.items():
        r.hincrby(f'{DB_PREFIX}{REDIS_HASH_TRAFFIC_PER_PROTOCOL}', k, v)

    # save raw records to DB:
    with db.cursor() as c:
        # to use execute_values, we need an iterator which will feed our data:
        def _get_data(flows, ts, client_ip, version):
            for flow in flows:
                ts_str = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                yield (version, client_ip, ts_str, flow,)
        data_iterator = _get_data(flows, ts, client_ip, version)

        psycopg2.extras.execute_values(c, f"INSERT INTO {DB_PREFIX}flows (version, client, ts, data) VALUES %s", data_iterator, "(%s, %s, %s, %s)", page_size=100)


if __name__ == "__main__":
    NAMED_PIPE_FILENAME = os.environ.get('NAMED_PIPE_FILENAME', None)
    if not NAMED_PIPE_FILENAME:
        raise Exception("Please specify NAMED_PIPE_FILENAME environment var")

    try:
        process_named_pipe(NAMED_PIPE_FILENAME)
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt -> exit")
        pass
