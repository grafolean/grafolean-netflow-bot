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


logging.basicConfig(format='%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s',
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
        with open(named_pipe_filename, "rb") as fp:
            log.info(f"Opened named pipe {named_pipe_filename}")
            for line in fp:
                if len(line) == 0:
                    log.info("Named pipe closed")
                    break

                write_record(json.loads(line))


def write_record(j):
    # {
    #   "DST_AS": 0,
    #   "SRC_AS": 0,
    #   "IN_PKTS": 1,  # Incoming counter with length N x 8 bits for the number of packets associated with an IP Flow
    #   "SRC_TOS": 0,
    #   "DST_MASK": 0,
    #   "IN_BYTES": 52,  # Incoming counter with length N x 8 bits for number of bytes associated with an IP Flow.
    #   "PROTOCOL": 6,  # IP protocol
    #   "SRC_MASK": 25,
    #   "DIRECTION": 0,  # Flow direction: 0 - ingress flow, 1 - egress flow
    #   "TCP_FLAGS": 20,
    #   "INPUT_SNMP": 17,  # Input interface index
    #   "L4_SRC_PORT": 36458,  # TCP/UDP source port number
    #   "L4_DST_PORT": 443,  # TCP/UDP destination port number
    #   "OUTPUT_SNMP": 3,  # Output interface index
    #   "IPV4_DST_ADDR": "1.2.3.4",
    #   "IPV4_NEXT_HOP": 1385497089,
    #   "IPV4_SRC_ADDR": "4.3.2.1",
    #   "LAST_SWITCHED": 2222830592,
    #   "FIRST_SWITCHED": 2222830592,
    #   "FLOW_SAMPLER_ID": 0,
    #   "UNKNOWN_FIELD_TYPE": 0
    # }
    # https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html#wp9001622

    with db.cursor() as c:
        # first save the flow record:
        ts = j['ts']
        log.info(f"Received record [{j['seq']}]: {datetime.utcfromtimestamp(ts)} from {j['client']}")
        c.execute(f"INSERT INTO {DB_PREFIX}records (ts, client_ip) VALUES (%s, %s) RETURNING seq;", (ts, j['client'],))
        record_db_seq = c.fetchone()[0]

        # then save each of the flows within the record, but use execute_values() to perform bulk insert:
        def _get_data(record_db_seq, flows):
            for flow in flows:
                yield (
                    record_db_seq,
                    flow.get('IN_BYTES'),
                    flow.get('PROTOCOL'),
                    flow.get('DIRECTION'),
                    flow.get('L4_DST_PORT'),
                    flow.get('L4_SRC_PORT'),
                    flow.get('INPUT_SNMP'),
                    flow.get('OUTPUT_SNMP'),
                    flow.get('IPV4_DST_ADDR'),
                    flow.get('IPV4_SRC_ADDR'),
                )
        data_iterator = _get_data(record_db_seq, j['flows'])
        psycopg2.extras.execute_values(
            c,
            f"INSERT INTO {DB_PREFIX}flows (record, IN_BYTES, PROTOCOL, DIRECTION, L4_DST_PORT, L4_SRC_PORT, INPUT_SNMP, OUTPUT_SNMP, IPV4_DST_ADDR, IPV4_SRC_ADDR) VALUES %s",
            data_iterator,
            "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            page_size=100
        )

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
