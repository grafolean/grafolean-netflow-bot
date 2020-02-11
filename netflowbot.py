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
from lookup import PROTOCOLS, DIRECTION_INGRESS, DIRECTION_EGRESS

logging.basicConfig(format='%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "base"))


def _get_last_used_seq(job_id):
    with db.cursor() as c:
        c.execute(f'SELECT j.last_used_seq, r.ts FROM {DB_PREFIX}bot_jobs j, {DB_PREFIX}records r WHERE j.id = %s and j.last_used_seq == r.seq;', (job_id,))
        last_used_seq, ts = c.fetchone()
        return last_used_seq, ts

def _get_current_max_seq():
    with db.cursor() as c:
        c.execute(f"SELECT MAX(seq) FROM {DB_PREFIX}records;")
        max_seq, = c.fetchone()
        return max_seq

def _save_current_max_seq(job_id, seq):
    with db.cursor() as c:
        c.execute(f"INSERT INTO {DB_PREFIX}bot_jobs (job_id, last_used_seq) VALUES (%s, %s) ON CONFLICT (job_id) DO UPDATE SET last_used_seq = %s;", (job_id, seq, seq))


def get_entities():
    requests.get()

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
        job_id = '1min'
        intervals = [60]
        job_params = {
            "job_id": job_id,
            "interval_slug": '1min',
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

        # job_id = '1h'
        # intervals = [3600]
        # job_params = {
        #     "job_id": job_id,
        #     "interval_slug": '1h',
        #     "entity_info": {
        #         "account_id": 129104112,
        #         "entity_id": 236477687,
        #         "entity_type": "device",
        #         "details": {
        #             "ipv4": "1.2.3.4"
        #         },
        #     },
        #     "backend_url": self.backend_url,
        #     "bot_token": self.bot_token,
        # }
        # yield job_id, intervals, NetFlowBot.perform_job, job_params

        # job_id = '24h'
        # intervals = [3600 * 24]
        # job_params = {
        #     "job_id": job_id,
        #     "interval_slug": '24h',
        #     "entity_info": {
        #         "account_id": 129104112,
        #         "entity_id": 236477687,
        #         "entity_type": "device",
        #         "details": {
        #             "ipv4": "1.2.3.4"
        #         },
        #     },
        #     "backend_url": self.backend_url,
        #     "bot_token": self.bot_token,
        # }
        # yield job_id, intervals, NetFlowBot.perform_job, job_params


    # This method is called whenever the job needs to be done. It gets the parameters and performs fetching of data.
    @staticmethod
    def perform_job(*args, **job_params):
        # \d netflow_flows
        #    Column        | Type     | Description
        #   ---------------+----------+-------------
        #    record        | integer  | // FK -> netflow_records.seq (PK)
        #    in_bytes      | integer  | number of bytes associated with an IP Flow
        #    protocol      | smallint | IP protocol (see lookup.py -> PROTOCOLS)
        #    direction     | smallint | flow direction: 0 - ingress flow, 1 - egress flow
        #    l4_dst_port   | integer  | destination port
        #    l4_src_port   | integer  | source port
        #    input_snmp    | smallint | input interface index
        #    output_snmp   | smallint | output interface index
        #    ipv4_src_addr | text     | source IP
        #    ipv4_dst_addr | text     | destination IP
        #   ---------------+----------+-------------

        job_id = job_params["job_id"]
        interval_slug = job_params["interval_slug"]

        entity_id = entity_ip = interface_index = None
        entity_info = job_params.get("entity_info", None)
        if entity_info is not None:
            entity_id = entity_info["entity_id"]
            entity_ip = entity_info["details"]["ipv4"]
            interface_index = entity_info.get("interface_index", None)


        last_used_seq, last_used_ts = _get_last_used_seq(job_id)
        max_seq = _get_current_max_seq()
        _save_current_max_seq(job_id, max_seq)

        values = []
        for direction in [DIRECTION_EGRESS, DIRECTION_INGRESS]:
            values.extend(NetFlowBot.get_traffic_all_entities(interval_slug, last_used_seq, max_seq, direction=direction))


        # values.extend(NetFlowBot.get_traffic(interval_slug, last_used_seq, max_seq, direction=DIRECTION_EGRESS, entity=entity_id, entity_ip=entity_ip, interface=interface_index))
        # values.extend(NetFlowBot.get_traffic(interval_slug, last_used_seq, max_seq, direction=DIRECTION_INGRESS, entity=entity_id, entity_ip=entity_ip, interface=interface_index))

        # values.extend(NetFlowBot.get_top_protocols(interval_slug, last_used_seq, max_seq, direction=DIRECTION_EGRESS, entity=entity_id, entity_ip=entity_ip, interface=interface_index, n=15))
        # values.extend(NetFlowBot.get_top_protocols(interval_slug, last_used_seq, max_seq, direction=DIRECTION_INGRESS, entity=entity_id, entity_ip=entity_ip, interface=interface_index, n=15))

        # values.extend(NetFlowBot.get_top_IPs(interval_slug, last_used_seq, max_seq, direction=DIRECTION_EGRESS, entity=entity_id, entity_ip=entity_ip, interface=interface_index, n=15))
        # values.extend(NetFlowBot.get_top_IPs(interval_slug, last_used_seq, max_seq, direction=DIRECTION_INGRESS, entity=entity_id, entity_ip=entity_ip, interface=interface_index, n=15))


        # protocol_str = 'TCP'
        # ipv4_dst_addr = '1.2.3.4'
        # ipv4_src_addr = '4.3.2.1'
        # # traffic on all devices, all interfaces, per ingress / egress:
        # f'netflow.{interval_slug}.egress'
        # f'netflow.{interval_slug}.ingress'
        # # traffic on all devices, all interfaces, per ingress / egress, for top X protocols:
        # f'netflow.{interval_slug}.egress.protocol.{protocol_str}'
        # f'netflow.{interval_slug}.ingress.protocol.{protocol_str}'
        # # traffic on all devices, all interfaces, per ingress / egress, for top X ips:
        # f'netflow.{interval_slug}.egress.ip.{ipv4_dst_addr}'
        # f'netflow.{interval_slug}.ingress.ip.{ipv4_src_addr}'

        # # traffic on all interfaces, per device, per ingress / egress:
        # f'netflow.{interval_slug}.egress.entity.{entity_id}'
        # f'netflow.{interval_slug}.ingress.entity.{entity_id}'
        # # traffic on all interfaces, per device, per ingress / egress, for top X protocols:
        # f'netflow.{interval_slug}.egress.entity.{entity_id}.protocol.{protocol_str}'
        # f'netflow.{interval_slug}.ingress.entity.{entity_id}.protocol.{protocol_str}'
        # # traffic on all interfaces, per device, per ingress / egress, for top X ips:
        # f'netflow.{interval_slug}.egress.entity.{entity_id}.ip.{ipv4_dst_addr}'
        # f'netflow.{interval_slug}.ingress.entity.{entity_id}.ip.{ipv4_src_addr}'

        # # traffic per interface, per device, per ingress / egress:
        # f'netflow.{interval_slug}.egress.entity.{entity_id}.if.{output_snmp}'
        # f'netflow.{interval_slug}.ingress.entity.{entity_id}.if.{input_snmp}'
        # # traffic per interface, per device, per ingress / egress, for top X protocols:
        # f'netflow.{interval_slug}.egress.entity.{entity_id}.if.{output_snmp}.protocol.{protocol_str}'
        # f'netflow.{interval_slug}.ingress.entity.{entity_id}.if.{input_snmp}.protocol.{protocol_str}'
        # # traffic per interface, per device, per ingress / egress, for top X ips:
        # f'netflow.{interval_slug}.egress.entity.{entity_id}.if.{output_snmp}.ip.{ipv4_dst_addr}'
        # f'netflow.{interval_slug}.ingress.entity.{entity_id}.if.{input_snmp}.ip.{ipv4_src_addr}'

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
    def construct_output_path_prefix(interval_slug, direction, entity, interface):
        prefix = f"netflow.{interval_slug}.{'ingress' if direction == DIRECTION_INGRESS else 'egress'}"
        if entity is None:
            return prefix
        prefix = f'{prefix}.entity.{entity}'
        if interface is None:
            return prefix
        prefix = f'{prefix}.if.{interface}'
        return prefix


    @staticmethod
    def get_traffic_all_entities(interval_slug, last_seq, max_seq, direction):
        output_path = NetFlowBot.construct_output_path_prefix(interval_slug, direction, entity=None, interface=None)
        with db.cursor() as c:
            c.execute(f"""
                SELECT
                    sum(f.in_bytes)
                FROM
                    {DB_PREFIX}records "r",
                    {DB_PREFIX}flows "f"
                WHERE
                    r.seq > %s AND
                    r.ts <= %s AND
                    r.seq = f.record AND
                    f.direction = %s
            """, (last_seq, max_seq, direction))
            values = []
            traffic_bytes, = c.fetchone()
            values.append({
                'p': output_path,
                'v': traffic_bytes,  # Bps
            })
            return values


    @staticmethod
    def get_traffic(interval_slug, last_seq, max_seq, direction, entity=None, interface=None):
        output_path = NetFlowBot.construct_output_path_prefix(interval_slug, direction, entity, interface)
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
                output_path = f'{output_path_prefix}.{interface_index}.if{interface_index}'
                values.append({
                    'p': output_path,
                    'v': traffic_bytes / 60.,  # Bps
                })
            return values
        return []

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
                    f.IPV4_{'SRC' if is_direction_in else 'DST'}_ADDR,
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
                    f.IPV4_{'SRC' if is_direction_in else 'DST'}_ADDR
                ORDER BY
                    traffic desc
                LIMIT 10;
            """, (from_time, to_time, interface_index,))

            values = []
            for top_ip, traffic_bytes in c.fetchall():
                output_path = f"{output_path_prefix}.topip.{'in' if is_direction_in else 'out'}.{interface_index}.if{interface_index}.{top_ip}"
                values.append({
                    'p': output_path,
                    'v': traffic_bytes / 60.,  # Bps
                })
            return values

    @staticmethod
    def get_top_N_protocols(output_path_prefix, from_time, to_time, interface_index, is_direction_in=True):
        with db.cursor() as c:
            # TODO: missing check for IP: r.client_ip = %s AND
            c.execute(f"""
                SELECT
                    f.PROTOCOL,
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
                    f.PROTOCOL
                ORDER BY
                    traffic desc
                LIMIT 10;
            """, (from_time, to_time, interface_index,))

            values = []
            for protocol, traffic_bytes in c.fetchall():
                output_path = f"{output_path_prefix}.topproto.{'in' if is_direction_in else 'out'}.{interface_index}.if{interface_index}.{protocol}.{PROTOCOLS[protocol]}"
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
