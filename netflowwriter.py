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

from lookup import PROTOCOLS
from dbutils import migrate_if_needed, db, DB_PREFIX


logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "base"))


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
    with db.cursor() as c:
        # first save the flow record:
        ts = datetime.utcfromtimestamp(j["ts"])
        c.execute(f"INSERT INTO {DB_PREFIX}records (ts, client_ip, version) VALUES (%s, %s, %s) RETURNING seq;", (ts, j['client'][0], j['version'],))
        record_seq = c.fetch_one()[0]

        # then save each of the flows within the record, but use execute_values() to perform bulk insert:
        def _get_data(record_seq, flows):
            for flow in flows:
                yield (record_seq, flow,)
        data_iterator = _get_data(record_seq, j['flows'])
        psycopg2.extras.execute_values(c, f"INSERT INTO {DB_PREFIX}flows (record, data) VALUES %s", data_iterator, "(%s, %s)", page_size=100)


if __name__ == "__main__":
    NAMED_PIPE_FILENAME = os.environ.get('NAMED_PIPE_FILENAME', None)
    if not NAMED_PIPE_FILENAME:
        raise Exception("Please specify NAMED_PIPE_FILENAME environment var")

    migrate_if_needed()
    try:
        process_named_pipe(NAMED_PIPE_FILENAME)
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt -> exit")
        pass