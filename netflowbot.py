import argparse
from datetime import datetime, timedelta
import gzip
import json
import logging
import os
import sys
import time
from collections import defaultdict

from colors import color
import dotenv
import requests

from grafoleancollector import Collector, send_results_to_grafolean
from dbutils import db, DB_PREFIX
from lookup import PROTOCOLS

logging.basicConfig(format='%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "base"))


class NetFlowBot(Collector):

    def jobs(self):
        # for entity_info in self.fetch_job_configs('netflow'):
        #     for sensor_info in entity_info["sensors"]:
        #         # The job could be triggered at different intervals - it is triggered when at least one of the specified intervals matches.
        #         intervals = [sensor_info["interval"]]
        #         # `job_id` must be a unique, permanent identifier of a job. When the job_id changes, the job will be rescheduled - so make sure it is something that
        #         # identifies this particular job.
        #         job_id = str(sensor_info["sensor_id"])
        #         # Prepare parameters that will be passed to `perform_job()` whenever the job is being run:
        #         # (don't forget to pass backend_url and bot_token!)
        #         job_params = { **sensor_info, "entity_info": entity_info, "backend_url": self.backend_url, "bot_token": self.bot_token }
        #         yield job_id, intervals, NetFlowBot.perform_job, job_params

        # mock the jobs for now: (until frontend is done)
        job_id = 'traffic_in'
        intervals = [60]
        job_params = {
            "job_id": job_id,
            "entity_info": {
                "account_id": 129104112,
                "entity_id": 236477687,
                "entity_type": "device",
                "details": {
                    "ipv4": "1.2.3.4"
                },
            },
            "backend_url": self.backend_url,
            "bot_token": self.bot_token,
        }
        yield job_id, intervals, NetFlowBot.perform_job, job_params

    # This method is called whenever the job needs to be done. It gets the parameters and performs fetching of data.
    @staticmethod
    def perform_job(*args, **job_params):
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

        entity_info = job_params["entity_info"]
        output_path_prefix = f'entity.{entity_info["entity_id"]}.netflow'

        minute_ago = datetime.now() - timedelta(minutes=1)
        two_minutes_ago = minute_ago - timedelta(minutes=1)

        values = []
        # Traffic in and out: (per interface)
        values.extend(NetFlowBot.get_values_traffic_in(output_path_prefix, two_minutes_ago, minute_ago))
        values.extend(NetFlowBot.get_values_traffic_out(output_path_prefix, two_minutes_ago, minute_ago))
        values.extend(NetFlowBot.get_top_N_IPs(output_path_prefix, two_minutes_ago, minute_ago, 18, is_direction_in=True))
        values.extend(NetFlowBot.get_top_N_IPs(output_path_prefix, two_minutes_ago, minute_ago, 18, is_direction_in=False))

        if not values:
            log.warning("No values found to be sent to Grafolean")
            return

        # send the data to Grafolean:
        send_results_to_grafolean(
            job_params['backend_url'],
            job_params['bot_token'],
            job_params['entity_info']['account_id'],
            values,
        )

    @staticmethod
    def get_values_traffic_in(output_path_prefix, from_time, to_time):
        with db.cursor() as c:
            # TODO: missing check for IP: r.client_ip = %s AND
            c.execute(f"""
                SELECT
                    f.INPUT_SNMP,
                    sum(f.IN_BYTES)
                FROM
                    {DB_PREFIX}records "r",
                    {DB_PREFIX}flows "f"
                WHERE
                    r.ts >= %s AND
                    r.ts < %s AND
                    r.seq = f.record AND
                    f.DIRECTION = 0
                GROUP BY
                    f.INPUT_SNMP
            """, (from_time, to_time,))

            values = []
            for interface_index, traffic_bytes in c.fetchall():
                output_path = f'{output_path_prefix}.traffic_in.{interface_index}.if{interface_index}'
                values.append({
                    'p': output_path,
                    'v': traffic_bytes / 60.,  # Bps
                })
            return values

    @staticmethod
    def get_values_traffic_out(output_path_prefix, from_time, to_time):
        with db.cursor() as c:
            # TODO: missing check for IP: r.client_ip = %s AND
            c.execute(f"""
                SELECT
                    f.OUTPUT_SNMP,
                    sum(f.IN_BYTES)
                FROM
                    {DB_PREFIX}records "r",
                    {DB_PREFIX}flows "f"
                WHERE
                    r.ts >= %s AND
                    r.ts < %s AND
                    r.seq = f.record AND
                    f.DIRECTION = 1
                GROUP BY
                    f.OUTPUT_SNMP
            """, (from_time, to_time,))

            values = []
            for interface_index, traffic_bytes in c.fetchall():
                output_path = f'{output_path_prefix}.traffic_out.{interface_index}.if{interface_index}'
                values.append({
                    'p': output_path,
                    'v': traffic_bytes / 60.,  # Bps
                })
            return values

    @staticmethod
    def get_top_N_IPs(output_path_prefix, from_time, to_time, interface_index, is_direction_in=True):
        with db.cursor() as c:
            # TODO: missing check for IP: r.client_ip = %s AND
            c.execute(f"""
                SELECT
                    f.IPV4_DST_ADDR,
                    sum(f.IN_BYTES) "traffic"
                FROM
                    netflow_records "r",
                    netflow_flows "f"
                WHERE
                    r.ts >= %s AND
                    r.ts < %s AND
                    r.seq = f.record AND
                    f.{'INPUT_SNMP' if is_direction_in else 'OUTPUT_SNMP'} = %s AND
                    f.DIRECTION = {'0' if is_direction_in else '1'}
                GROUP BY
                    f.IPV4_DST_ADDR
                ORDER BY
                    traffic desc
                LIMIT 10;
            """, (from_time, to_time, interface_index,))

#SELECT f.data->'IPV4_DST_ADDR', sum((f.data->'IN_BYTES')::integer) "traffic" FROM netflow_records "r", netflow_flows "f" WHERE r.ts >= now() - interval '1 minute' AND r.seq = f.record AND (f.data->'INPUT_SNMP')::integer = 18 AND (f.data->'DIRECTION')::integer = '0' GROUP BY f.data->'IPV4_DST_ADDR' ORDER BY traffic desc LIMIT 10;

            values = []
            for top_ip, traffic_bytes in c.fetchall():
                output_path = f"{output_path_prefix}.topip.{'in' if is_direction_in else 'out'}.{interface_index}.if{interface_index}.{top_ip}"
                values.append({
                    'p': output_path,
                    'v': traffic_bytes / 60.,  # Bps
                })
            return values


def wait_for_grafolean(backend_url):
    while True:
        url = '{}/status/info'.format(backend_url)
        log.info("Checking Grafolean status...")
        try:
            r = requests.get(url)
            r.raise_for_status()
            status_info = r.json()
            if status_info['db_migration_needed'] == False and status_info['user_exists'] == True:
                log.info("Grafolean backend is ready.")
                return
        except:
            pass
        log.info("Grafolean backend not available / initialized yet, waiting.")
        time.sleep(10)


if __name__ == "__main__":
    dotenv.load_dotenv()

    backend_url = os.environ.get('BACKEND_URL')
    jobs_refresh_interval = int(os.environ.get('JOBS_REFRESH_INTERVAL', 120))

    if not backend_url:
        raise Exception("Please specify BACKEND_URL env var.")

    wait_for_grafolean(backend_url)

    bot_token = os.environ.get('BOT_TOKEN')
    if not bot_token:
        # bot token can also be specified via contents of a file:
        bot_token_from_file = os.environ.get('BOT_TOKEN_FROM_FILE')
        if bot_token_from_file:
            with open(bot_token_from_file, 'rt') as f:
                bot_token = f.read()
    if not bot_token:
        raise Exception("Please specify BOT_TOKEN / BOT_TOKEN_FROM_FILE env var.")

    b = NetFlowBot(backend_url, bot_token, jobs_refresh_interval)
    b.execute()
