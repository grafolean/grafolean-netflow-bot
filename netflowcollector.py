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


logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "base"))


def process_netflow(netflow_port, named_pipe_filename):
    # endless loop - read netflow packets, encode them to JSON and write them to named pipe:
    with open(named_pipe_filename, "wb", 0) as fp:
        for ts, client, export in get_export_packets('0.0.0.0', NETFLOW_PORT):
            entry = {
                "ts": ts,
                "client": client,
                "version": export.header.version,
                "flows": [flow.data for flow in export.flows],
            }
            line = json.dumps(entry).encode() + b'\n'
            fp.write(line)


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
