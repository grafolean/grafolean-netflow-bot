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
from dbutils import initial_wait_for_db, migrate_if_needed, get_db_cursor, DB_PREFIX, DBConnectionError
from lookup import DIRECTION_INGRESS


# python-netflow-v9-softflowd expects main.py to be the main entrypoint, but we only need
# parse_packet():
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/pynetflow')
from pynetflow.netflow import parse_packet
from pynetflow.netflow.utils import UnknownExportVersion
from pynetflow.netflow.v9 import V9TemplateNotRecognized


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
# "To determine the appropriate binary format for the actual tuple data you should consult the PostgreSQL
#  source, in particular the *send and *recv functions for each column's data type (typically these functions
#  are found in the src/backend/utils/adt/ directory of the source distribution)."
# 4-byte INETv4/v6 prefix: family, netmask, is_cidr, n bytes
# https://doxygen.postgresql.org/network_8c_source.html#l00193
IPV4_ADDRESS_PREFIX = struct.pack('!BBBB', socket.AF_INET, 32, 0, 4)
# Gotcha: IPv6 address family in Postgres is *not* socket.AF_INET6 (10),
# instead it is defined as socket.AF_INET + 1 (2 + 1 == 3)
# https://doxygen.postgresql.org/utils_2inet_8h_source.html#l00040
IPV6_ADDRESS_PREFIX = struct.pack('!BBBB', socket.AF_INET + 1, 128, 0, 16)
# Timestamp is encoded as signed number of microseconds from PG epoch
PG_EPOCH_TIMESTAMP = 946684800  # 2020-01-01T00:00:00Z


def _pgwriter_init():
    pg_writer = BytesIO()
    pg_writer.write(PG_COPYFROM_INIT)
    return pg_writer


def _pgwriter_encode(ts, client_ip, IN_BYTES, PROTOCOL, DIRECTION, L4_DST_PORT, L4_SRC_PORT, INPUT_SNMP, OUTPUT_SNMP, address_family, IPVx_DST_ADDR, IPVx_SRC_ADDR):
    buf = struct.pack('!Hiqi4s4siQiHiHiIiIiQiQ',
        11,  # number of columns
        8, int(1000000 * (ts - PG_EPOCH_TIMESTAMP)), # https://doxygen.postgresql.org/backend_2utils_2adt_2timestamp_8c_source.html#l00228
        8, IPV4_ADDRESS_PREFIX, socket.inet_aton(client_ip),   # 4 bytes prefix + 4 bytes IP
        8, IN_BYTES,                      # bigint
        2, PROTOCOL,
        2, DIRECTION,
        4, L4_DST_PORT,
        4, L4_SRC_PORT,
        8, INPUT_SNMP,
        8, OUTPUT_SNMP,
    )
    if address_family != socket.AF_INET6:
        buf2 = struct.pack('!i4s4si4s4s',
            8, IPV4_ADDRESS_PREFIX, IPVx_DST_ADDR,
            8, IPV4_ADDRESS_PREFIX, IPVx_SRC_ADDR,
        )
    else:
        buf2 = struct.pack('!i4s16si4s16s',
            4 + 16, IPV6_ADDRESS_PREFIX, IPVx_DST_ADDR,
            4 + 16, IPV6_ADDRESS_PREFIX, IPVx_SRC_ADDR,
        )
    return buf + buf2


def _pgwriter_finish(pgwriter):
    try:
        with get_db_cursor() as c:
            pgwriter.write(struct.pack('!h', -1))
            pgwriter.seek(0)
            c.copy_expert(f"COPY {DB_PREFIX}flows2 FROM STDIN WITH BINARY", pgwriter)
    except DBConnectionError:
        log.error("Error writing to DB, records lost!")
        return


def process_named_pipe(named_pipe_filename):
    try:
        os.mkfifo(named_pipe_filename)
    except OSError as ex:
        if ex.errno != errno.EEXIST:
            raise

    templates = {"netflow": {}, "ipfix": {}}
    last_record_seqs = {}
    buffer = []  # we merge together writes to DB
    known_exporters = set()
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

                    # if client_ip doesn't exist yet, mark it as unknown so that we can advise user to add it:
                    if client_ip not in known_exporters:
                        ensure_exporter(client_ip)
                        known_exporters.add(client_ip)
                        log.warning(f"[{client_ip}] New exporter!")

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
                            write_buffer(buffer)
                            buffer = []
                    except UnknownExportVersion:
                        log.warning("Unknown NetFlow version")
                        continue
                    except V9TemplateNotRecognized as ex:
                        log.warning(f"Failed to decode a v9 ExportPacket, template not recognized (if this happens at the start, it's ok)")
                        if client_ip in last_record_seqs:
                            last_record_seqs[client_ip] += 1
                        continue

                except Exception as ex:
                    log.exception("Error writing line, skipping...")


def ensure_exporter(client_ip):
    with get_db_cursor() as c:
        c.execute(f"INSERT INTO {DB_PREFIX}exporters (ip) VALUES (%s) ON CONFLICT DO NOTHING;", (client_ip,))


def write_buffer(buffer):
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


    log.debug(f"Writing {len(buffer)} records to DB")
    # save each of the flows within the record, but use execute_values() to perform bulk insert:
    def _get_data(buffer):
        for ts, client_ip, export in buffer:
            netflow_version, flows = export.header.version, export.flows
            if netflow_version == 9:
                for f in flows:
                    try:
                        # if f.data.get("IP_PROTOCOL_VERSION", 4) == 6:
                        if not f.data.get("IPV6_DST_ADDR", None) is None:
                            address_family = socket.AF_INET6
                            dst = socket.inet_pton(address_family, f.data["IPV6_DST_ADDR"])
                            src = socket.inet_pton(address_family, f.data["IPV6_SRC_ADDR"])
                        else:
                            address_family = socket.AF_INET
                            dst = socket.inet_aton(f.data["IPV4_DST_ADDR"])
                            src = socket.inet_aton(f.data["IPV4_SRC_ADDR"])

                        yield _pgwriter_encode(
                            ts,
                            client_ip,
                            f.data["IN_BYTES"],
                            f.data["PROTOCOL"],
                            f.data.get("DIRECTION", DIRECTION_INGRESS),
                            f.data.get("L4_DST_PORT", 0),  # sometimes ports are not available: https://github.com/grafolean/grafolean/issues/13
                            f.data.get("L4_SRC_PORT", 0),
                            f.data.get("INPUT_SNMP", 0),
                            f.data.get("OUTPUT_SNMP", 0),  # sometimes OUTPUT_SNMP is not available: https://github.com/grafolean/grafolean/issues/41 - not sure about INPUT_SNMP, better safe...
                            address_family,
                            dst,
                            src,
                        )
                    except:
                        log.exception(f"[{client_ip}] Error decoding v9 flow. Contents: {repr(f.data)}")
            elif netflow_version == 5:
                for f in flows:
                    try:
                        yield _pgwriter_encode(
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
                            # address_family is always IPv4:
                            socket.AF_INET,
                            # netflow v5 IP addresses are decoded to integers, which is less suitable for us - pack
                            # them back to bytes:
                            # "IPV4_DST_ADDR":
                            struct.pack('!I', f.data["IPV4_DST_ADDR"]),
                            # "IPV4_SRC_ADDR":
                            struct.pack('!I', f.data["IPV4_SRC_ADDR"]),
                        )
                    except:
                        log.exception(f"[{client_ip}] Error decoding v5 flow. Contents: {repr(f.data)}")
            else:
                log.error(f"[{client_ip}] Only Netflow v5 and v9 currently supported, ignoring record (version: [{export.header.version}])")

    pgwriter = _pgwriter_init()
    for encoded_data in _get_data(buffer):
        pgwriter.write(encoded_data)
    _pgwriter_finish(pgwriter)


if __name__ == "__main__":
    NAMED_PIPE_FILENAME = os.environ.get('NAMED_PIPE_FILENAME', None)
    if not NAMED_PIPE_FILENAME:
        raise Exception("Please specify NAMED_PIPE_FILENAME environment var")

    initial_wait_for_db()
    migrate_if_needed()

    try:
        process_named_pipe(NAMED_PIPE_FILENAME)
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt -> exit")
        pass
