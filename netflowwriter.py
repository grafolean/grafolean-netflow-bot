import argparse
import base64
import gzip
import json
import logging
import os
import errno
import sys
import socket
import struct
import time
from collections import defaultdict
from datetime import datetime

import psycopg2.extras
from colors import color

from lookup import PROTOCOLS
from dbutils import migrate_if_needed, get_db_cursor, DB_PREFIX
from lookup import DIRECTION_INGRESS


# python-netflow-v9-softflowd expects main.py to be the main entrypoint, but we only need
# parse_packet():
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/pynetflow')
from pynetflow.netflow import parse_packet, UnknownNetFlowVersion, TemplateNotRecognized


IS_DEBUG = os.environ.get('DEBUG', 'false') in ['true', 'yes', '1']
logging.basicConfig(format='%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG if IS_DEBUG else logging.INFO)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "writer"))


# Amount of time to wait before dropping an undecodable ExportPacket
PACKET_TIMEOUT = 60 * 60

def process_named_pipe(named_pipe_filename):
    try:
        os.mkfifo(named_pipe_filename)
    except OSError as ex:
        if ex.errno != errno.EEXIST:
            raise

    templates = {}
    while True:
        with open(named_pipe_filename, "rb") as fp:
            log.info(f"Opened named pipe {named_pipe_filename}")
            for line in fp:
                if len(line) == 0:
                    log.warning("Named pipe closed")
                    time.sleep(0.1)
                    break

                try:
                    data_b64, ts, client = json.loads(line)
                    data = base64.b64decode(data_b64)

                    try:
                        export = parse_packet(data, templates)
                        write_record(ts, client, export)
                    except UnknownNetFlowVersion:
                        log.warning("Unknown NetFlow version")
                        continue
                    except TemplateNotRecognized:
                        log.warning("Failed to decode a v9 ExportPacket, template not "
                            "recognized (if this happens at the start, it's ok)")
                        continue

                except Exception as ex:
                    log.exception("Error writing line, skipping...")


last_record_seqs = {}


def write_record(ts, client, export):
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

    client_ip, _ = client

    # check for missing NetFlow records:
    last_record_seq = last_record_seqs.get(client_ip)
    if last_record_seq is None:
        log.warning(f"Last record sequence number is not known, starting with {export.header.sequence}")
    elif export.header.sequence != last_record_seq + 1:
        log.error(f"Sequence number ({export.header.sequence}) does not follow ({last_record_seq}), some records might have been skipped")
    last_record_seqs[client_ip] = export.header.sequence

    log.debug(f"Received record [{export.header.sequence}]: {datetime.utcfromtimestamp(ts)} from {client_ip}")
    with get_db_cursor() as c:
        # save each of the flows within the record, but use execute_values() to perform bulk insert:
        def _get_data(netflow_version, ts, client_ip, flows):
            if netflow_version == 9:
                for f in flows:
                    yield (
                        ts,
                        client_ip,
                        # "IN_BYTES":
                        f.data["IN_BYTES"],
                        # "PROTOCOL":
                        f.data["PROTOCOL"],
                        # "DIRECTION":
                        f.data["DIRECTION"],
                        # "L4_DST_PORT":
                        f.data["L4_DST_PORT"],
                        # "L4_SRC_PORT":
                        f.data["L4_SRC_PORT"],
                        # "INPUT_SNMP":
                        f.data["INPUT_SNMP"],
                        # "OUTPUT_SNMP":
                        f.data["OUTPUT_SNMP"],
                        # "IPV4_DST_ADDR":
                        f.data["IPV4_DST_ADDR"],
                        # "IPV4_SRC_ADDR":
                        f.data["IPV4_SRC_ADDR"],
                    )
            elif netflow_version == 5:
                for f in flows:
                    yield (
                        ts,
                        client_ip,
                        # "IN_BYTES":
                        f.data["IN_OCTETS"],
                        # "PROTOCOL":
                        f.data["PROTO"],
                        # "DIRECTION":
                        DIRECTION_INGRESS,
                        # "L4_DST_PORT":
                        f.data["DST_PORT"],
                        # "L4_SRC_PORT":
                        f.data["SRC_PORT"],
                        # "INPUT_SNMP":
                        f.data["INPUT"],
                        # "OUTPUT_SNMP":
                        f.data["OUTPUT"],
                        # netflow v5 IP addresses are decoded to integers, which is less suitable for us - pack
                        # them back to bytes and transform them to strings:
                        # "IPV4_DST_ADDR":
                        socket.inet_ntoa(struct.pack('!I', f.data["IPV4_DST_ADDR"])),
                        # "IPV4_SRC_ADDR":
                        socket.inet_ntoa(struct.pack('!I', f.data["IPV4_SRC_ADDR"])),
                    )
            else:
                log.error(f"Only Netflow v5 and v9 currently supported, ignoring record (version: [{export.header.version}])")
                return

        data_iterator = _get_data(export.header.version, ts, client_ip, export.flows)
        psycopg2.extras.execute_values(
            c,
            f"INSERT INTO {DB_PREFIX}flows (ts, client_ip, IN_BYTES, PROTOCOL, DIRECTION, L4_DST_PORT, L4_SRC_PORT, INPUT_SNMP, OUTPUT_SNMP, IPV4_DST_ADDR, IPV4_SRC_ADDR) VALUES %s",
            data_iterator,
            "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
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
