import argparse
import gzip
import json
import logging
import os
import sys
import time
from datetime import datetime

from colors import color


# python-netflow-v9-softflowd expects main.py to be the main entrypoint, but we only need
# get_export_packets() iterator:
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/pynetflow')
from pynetflow.main import get_export_packets
# disable DEBUG logging on NetFlow collector library:
logging.getLogger('pynetflow.main').setLevel(logging.INFO)


logging.basicConfig(format='%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "base"))


def process_netflow(netflow_port, named_pipe_filename):
    # endless loop - read netflow packets, encode them to JSON and write them to named pipe:
    line = None
    last_record_seqs = {}
    while True:
        try:
            with open(named_pipe_filename, "wb", 0) as fp:
                # if named pipe threq an error for some reason (BrokenPipe), write the line we
                # have in buffer before listening to new packets:
                if line is not None:
                    fp.write(line)
                    line = None
                for ts, client, export in get_export_packets('0.0.0.0', NETFLOW_PORT):
                    if export.header.version != 9:
                        log.error(f"Only Netflow v9 currently supported, ignoring record (version: [{export.header.version}])")
                        continue

                    client_ip, _ = client

                    # check for missing records:
                    last_record_seq = last_record_seqs.get(client_ip)
                    if last_record_seq is None:
                        log.warning(f"Last record sequence number is not known, starting with {export.header.sequence}")
                    elif export.header.sequence != last_record_seq + 1:
                        log.error(f"Sequence number ({export.header.sequence}) does not follow ({last_record_seq}), some records might have been skipped")
                    last_record_seqs[client_ip] = export.header.sequence

                    flows_data = [flow.data for flow in export.flows]
                    entry = {
                        "ts": ts,
                        "client": client_ip,
                        "seq": export.header.sequence,
                        "flows": [{
                            "IN_BYTES": data["IN_BYTES"],
                            "PROTOCOL": data["PROTOCOL"],
                            "DIRECTION": data["DIRECTION"],
                            "INPUT_SNMP": data["INPUT_SNMP"],
                            "L4_DST_PORT": data["L4_DST_PORT"],
                            "L4_SRC_PORT": data["L4_SRC_PORT"],
                            "OUTPUT_SNMP": data["OUTPUT_SNMP"],
                            "IPV4_DST_ADDR": data["IPV4_DST_ADDR"],
                            "IPV4_SRC_ADDR": data["IPV4_SRC_ADDR"],
                        } for data in flows_data],
                    }
                    line = json.dumps(entry).encode() + b'\n'
                    fp.write(line)
                    log.debug(f"Wrote seq [{export.header.sequence}] from client [{client_ip}], ts [{ts}], n flows: [{len(flows_data)}]")
                    line = None
        except Exception as ex:
            log.exception(f"Exception: {str(ex)}")



if __name__ == "__main__":

    NAMED_PIPE_FILENAME = os.environ.get('NAMED_PIPE_FILENAME', None)
    if not NAMED_PIPE_FILENAME:
        raise Exception("Please specify NAMED_PIPE_FILENAME environment var")

    # wait for named pipe to exist:
    while not os.path.exists(NAMED_PIPE_FILENAME):
        log.info(f"Named pipe {NAMED_PIPE_FILENAME} does not exist yet, waiting...")
        time.sleep(1.0)

    NETFLOW_PORT = int(os.environ.get('NETFLOW_PORT', 2055))
    log.info(f"Listening for NetFlow traffic on UDP port {NETFLOW_PORT}")

    try:
        process_netflow(NETFLOW_PORT, NAMED_PIPE_FILENAME)
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt -> exit")
        pass
