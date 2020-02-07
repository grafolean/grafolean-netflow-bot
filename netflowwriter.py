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

from lookup import PROTOCOLS, DB_PREFIX, DIRECTION_INGRESS


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
    #   "L4_DST_PORT": 443,  # TCP/UDP destination port number
    #   "L4_SRC_PORT": 36458,
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
    ts, seq, client_ip = j['ts'], j['seq'], j['client']
    log.info(f"Received record [{seq}]: {ts} from {client_ip}")

    for flow in j['flows']:
        in_bytes = flow.get('IN_BYTES')
        protocol = flow.get('PROTOCOL')
        direction = int(flow.get('DIRECTION'))
        l4_dst_port = flow.get('L4_DST_PORT')
        l4_src_port = flow.get('L4_SRC_PORT')
        input_snmp = flow.get('INPUT_SNMP')
        output_snmp = flow.get('OUTPUT_SNMP')
        ipv4_dst_addr = flow.get('IPV4_DST_ADDR')
        ipv4_src_addr = flow.get('IPV4_SRC_ADDR')

        protocol_str = PROTOCOLS.get(protocol, f'?{protocol}')
        entity_id = 123

        # traffic on all devices, all interfaces, per ingress / egress:
        gress = 'ingress' if direction == DIRECTION_INGRESS else 'egress'
        data[f'netflow.traffic.{gress}'] += in_bytes
        # traffic on all devices, all interfaces, per ingress / egress, per protocol:
        data[f'netflow.traffic.{gress}.protocol.{protocol_str}'] += in_bytes
        # traffic on all devices, all interfaces, per ingress / egress, per ip:
        ip = ipv4_src_addr if direction == DIRECTION_INGRESS else ipv4_dst_addr
        data[f'netflow.traffic.{gress}.ip.{ip}'] += in_bytes

        # traffic on all interfaces, per device, per ingress / egress:
        data[f'netflow.traffic.{gress}.entity.{entity_id}'] += in_bytes
        # traffic on all interfaces, per device, per ingress / egress, per protocol:
        data[f'netflow.traffic.{gress}.entity.{entity_id}.protocol.{protocol_str}'] += in_bytes
        # traffic on all interfaces, per device, per ingress / egress, per ip:
        data[f'netflow.traffic.{gress}.ip.{ip}'] += in_bytes

        # traffic per interface, per device, per ingress / egress:
        interface_index = input_snmp if direction == 0 else output_snmp
        data[f'netflow.traffic.{gress}.entity.{entity_id}.if.{interface_index}'] += in_bytes
        data[f'netflow.traffic.{gress}.entity.{entity_id}.if.{interface_index}.protocol.{protocol_str}'] += in_bytes


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
