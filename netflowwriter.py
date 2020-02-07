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

from colors import color
import redis

from lookup import PROTOCOLS, DB_PREFIX


logging.basicConfig(format='%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "base"))


REDIS_HOST = os.environ.get('REDIS_HOST', '127.0.0.1')
r = redis.Redis(host=REDIS_HOST)


def read_named_pipe(named_pipe_filename):
    try:
        os.mkfifo(named_pipe_filename)
    except OSError as ex:
        if ex.errno != errno.EEXIST:
            raise

    while True:
        # instead of constantly writing, save the counters to memory and
        # only flush them to Redis every X seconds:
        FLUSH_REDIS_S = 3.0

        next_flush = time.time() + FLUSH_REDIS_S
        data = defaultdict(int)
        with open(named_pipe_filename, 'rb') as fp:
            log.info(f"Opened named pipe {named_pipe_filename}")
            for line in fp:
                if len(line) == 0:
                    log.info("Named pipe closed")
                    break

                data = process_line(json.loads(line), data)

                now = time.time()
                if now < next_flush:
                    continue
                next_flush = now + FLUSH_REDIS_S

                for k, v in data.items():
                    r.hincrby(f'{DB_PREFIX}traffic_per_protocol', k, v)
                data = defaultdict(int)


def process_line(j, data):
    ts, seq, client_ip = j['ts'], j['seq'], j['client']
    log.info(f"Received record [{seq}]: {ts} from {client_ip}")

    for flow in j['flows']:
        in_bytes = flow.get('IN_BYTES')
        protocol = flow.get('PROTOCOL')
        direction = flow.get('DIRECTION')
        l4_dst_port = flow.get('L4_DST_PORT')
        l4_src_port = flow.get('L4_SRC_PORT')
        input_snmp = flow.get('INPUT_SNMP')
        output_snmp = flow.get('OUTPUT_SNMP')
        ipv4_dst_addr = flow.get('IPV4_DST_ADDR')
        ipv4_src_addr = flow.get('IPV4_SRC_ADDR')

        protocol_str = PROTOCOLS.get(protocol, f'?{protocol}')
        data[protocol_str] += in_bytes

    return data



if __name__ == "__main__":
    NAMED_PIPE_FILENAME = os.environ.get('NAMED_PIPE_FILENAME', None)
    if not NAMED_PIPE_FILENAME:
        raise Exception("Please specify NAMED_PIPE_FILENAME environment var")

    try:
        read_named_pipe(NAMED_PIPE_FILENAME)
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt -> exit")
        pass
