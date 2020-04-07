import argparse
import base64
import gzip
import json
import logging
import os
import socket
import struct
import sys
import time
from datetime import datetime

from colors import color


IS_DEBUG = os.environ.get('DEBUG', 'false') in ['true', 'yes', '1']
logging.basicConfig(format='%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG if IS_DEBUG else logging.INFO)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "collector"))


def pass_netflow_data(netflow_port, named_pipe_filename):
    # endless loop - read netflow packets from UDP port and write them to named pipe:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('', netflow_port,)  # '' binds to any IPv4 address (not IPv6!)
    log.debug('starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)

    MAX_BUF_SIZE = 4096
    BUFFERING_LINES = 1  # https://docs.python.org/2/library/functions.html#open
    while True:
        try:
            with open(named_pipe_filename, "wb", BUFFERING_LINES) as fp:
                data, address = sock.recvfrom(MAX_BUF_SIZE)
                now = time.time()
                line = json.dumps((base64.b64encode(data).decode(), now, address)).encode() + b'\n'
                fp.write(line)
                log.debug(f"Passing [{len(data)}] from client [{address[0]}], ts [{now}]")

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
        pass_netflow_data(NETFLOW_PORT, NAMED_PIPE_FILENAME)
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt -> exit")
        pass
