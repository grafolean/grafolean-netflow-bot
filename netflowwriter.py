import argparse
import base64
from datetime import datetime, timedelta
import gzip
from io import BytesIO
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
from dbutils import migrate_if_needed, get_db_cursor, DB_PREFIX, S_PER_PARTITION
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


# 11-byte signature (constructed in this way to detect possible mangled bytes), flags, header extension
# https://www.postgresql.org/docs/9.0/sql-copy.html#AEN59377
PG_COPYFROM_INIT = struct.pack('!11sII', b'PGCOPY\n\377\r\n\0', 0, 0)
# 4-byte INETv4 prefix: family, netmask, is_cidr, n bytes
# https://doxygen.postgresql.org/network_8c_source.html#l00193
IPV4_PREFIX = struct.pack('!BBBB', socket.AF_INET, 32, 0, 4)


def _pgwriter_init():
    pg_writer = BytesIO()
    pg_writer.write(PG_COPYFROM_INIT)
    return pg_writer


def _pgwriter_write(pgwriter, ts, client_ip, IN_BYTES, PROTOCOL, DIRECTION, L4_DST_PORT, L4_SRC_PORT, INPUT_SNMP, OUTPUT_SNMP, IPV4_DST_ADDR, IPV4_SRC_ADDR):
    buf = struct.pack('!HiIi4s4siIiHiHiIiIiHiHi4s4si4s4s',
        11,  # number of columns
        4, int(ts),                       # integer - beware of Y2038 problem! :)
        8, IPV4_PREFIX, socket.inet_aton(client_ip),   # 4 bytes prefix + 4 bytes IP
        4, IN_BYTES,                      # integer
        2, PROTOCOL,
        2, DIRECTION,
        4, L4_DST_PORT,
        4, L4_SRC_PORT,
        2, INPUT_SNMP,
        2, OUTPUT_SNMP,
        8, IPV4_PREFIX, IPV4_DST_ADDR,
        8, IPV4_PREFIX, IPV4_SRC_ADDR,
    )
    pgwriter.write(buf)


def _pgwriter_finish(pgwriter):
    with get_db_cursor() as c:
        pgwriter.write(struct.pack('!h', -1))
        pgwriter.seek(0)
        c.copy_expert(f"COPY {DB_PREFIX}flows FROM STDIN WITH BINARY", pgwriter)


def process_named_pipe(named_pipe_filename):
    try:
        os.mkfifo(named_pipe_filename)
    except OSError as ex:
        if ex.errno != errno.EEXIST:
            raise

    templates = {}
    last_record_seqs = {}
    last_partition_no = None
    buffer = []  # we merge together writes to DB
    MAX_BUFFER_SIZE = 5
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
                    client_ip, _ = client
                    data = base64.b64decode(data_b64)

                    # sequence number of the (24h) day from UNIX epoch helps us determine the
                    # DB partition we are working with:
                    partition_no = int(ts // S_PER_PARTITION)
                    if partition_no != last_partition_no:
                        write_buffer(buffer, last_partition_no)
                        ensure_flow_table_partition_exists(partition_no)
                        last_partition_no = partition_no

                    try:
                        export = parse_packet(data, templates)
                        log.debug(f"[{client_ip}] Received record [{export.header.sequence}]: {datetime.utcfromtimestamp(ts)}")

                        # check for missing NetFlow records:
                        last_record_seq = last_record_seqs.get(client_ip)
                        if last_record_seq is None:
                            log.warning(f"[{client_ip}] Last record sequence number is not known, starting with {export.header.sequence}")
                        elif export.header.sequence != last_record_seq + 1:
                            log.error(f"[{client_ip}] Sequence number ({export.header.sequence}) does not follow ({last_record_seq}), some records might have been skipped")
                        last_record_seqs[client_ip] = export.header.sequence

                        # append the record to a buffer and write to DB when buffer is full enough:
                        buffer.append((ts, client_ip, export,))
                        if len(buffer) > MAX_BUFFER_SIZE:
                            write_buffer(buffer, partition_no)
                            buffer = []
                    except UnknownNetFlowVersion:
                        log.warning("Unknown NetFlow version")
                        continue
                    except TemplateNotRecognized:
                        log.warning("Failed to decode a v9 ExportPacket, template not "
                            "recognized (if this happens at the start, it's ok)")
                        continue

                except Exception as ex:
                    log.exception("Error writing line, skipping...")


# Based on timestamp, make sure that the partition exists:
def ensure_flow_table_partition_exists(partition_no):
    ts_start = partition_no * S_PER_PARTITION
    ts_end = ts_start + S_PER_PARTITION
    with get_db_cursor() as c:
        # "When creating a range partition, the lower bound specified with FROM is an inclusive bound, whereas
        #  the upper bound specified with TO is an exclusive bound."
        # https://www.postgresql.org/docs/12/sql-createtable.html
        c.execute(f"CREATE UNLOGGED TABLE IF NOT EXISTS {DB_PREFIX}flows_{partition_no} PARTITION OF {DB_PREFIX}flows FOR VALUES FROM ({ts_start}) TO ({ts_end})")
        return partition_no


def write_buffer(buffer, partition_no):
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


    log.debug(f"Writing {len(buffer)} records to DB, partition {partition_no}")
    # save each of the flows within the record, but use execute_values() to perform bulk insert:
    def _get_data(buffer):
        for ts, client_ip, export in buffer:
            netflow_version, flows = export.header.version, export.flows
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
                        socket.inet_aton(f.data["IPV4_DST_ADDR"]),
                        # "IPV4_SRC_ADDR":
                        socket.inet_aton(f.data["IPV4_SRC_ADDR"]),
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
                        # them back to bytes:
                        # "IPV4_DST_ADDR":
                        struct.pack('!I', f.data["IPV4_DST_ADDR"]),
                        # "IPV4_SRC_ADDR":
                        struct.pack('!I', f.data["IPV4_SRC_ADDR"]),
                    )
            else:
                log.error(f"[{client_ip}] Only Netflow v5 and v9 currently supported, ignoring record (version: [{export.header.version}])")

    pgwriter = _pgwriter_init()
    for data in _get_data(buffer):
        _pgwriter_write(pgwriter, *data)
    _pgwriter_finish(pgwriter)


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
