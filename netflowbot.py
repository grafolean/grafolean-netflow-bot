import argparse
from datetime import datetime, timedelta
import gzip
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict

from colors import color
import dotenv
import requests

from grafoleancollector import Collector, send_results_to_grafolean
from dbutils import get_db_cursor, DB_PREFIX, S_PER_PARTITION, LEAVE_N_PAST_PARTITIONS
from lookup import PROTOCOLS, DIRECTION_INGRESS, DIRECTION_EGRESS

logging.basicConfig(format='%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "bot"))


NETFLOW_AGGREGATION_INTERVALS = [
    # label; interval; when to start first run (to make sure the runs are not aligned)
    ('1min', 60, 0),
    ('15min', 15 * 60, 15),
    ('1h', 3600, 4*60 + 15),
    ('4h', 4 * 3600, 29*60 + 15),
    ('24h', 24 * 3600, 1*3600 + 29*60 + 15),
]
TOP_N_MAX = 10


# Decorator: to avoid overwhelming the system, we sleep some amount after performing
# demanding tasks. For how long? Some factor of the timed interval.
def slow_down(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        ret = func(*args, **kwargs)
        end = time.time()
        time.sleep((end - start) * 0.5)
        return ret
    return wrapper


def path_part_encode(s):
    return s.replace(".", '%2e')


def _get_last_used_ts(job_id):
    with get_db_cursor() as c:
        c.execute(f'SELECT j.last_used_ts FROM {DB_PREFIX}bot_jobs j WHERE j.job_id = %s;', (job_id,))
        rec = c.fetchone()
        if rec is None:
            return None
        last_used_ts, = rec
        return int(last_used_ts)

def _get_current_max_ts():
    with get_db_cursor() as c:
        c.execute(f"SELECT MAX(ts) FROM {DB_PREFIX}flows;")
        rec = c.fetchone()
        if rec is None:
            return None
        max_ts, = rec
        return max_ts

def _save_current_max_ts(job_id, max_ts):
    with get_db_cursor() as c:
        c.execute(f"INSERT INTO {DB_PREFIX}bot_jobs (job_id, last_used_ts) VALUES (%s, %s) ON CONFLICT (job_id) DO UPDATE SET last_used_ts = %s;", (job_id, max_ts, max_ts))


def job_maint_remove_old_partitions(*args, **kwargs):
    with get_db_cursor() as c:
        log.info("MAINT: Maintenance started - removing old partitions")
        today_seq = int(time.time() // S_PER_PARTITION)
        c.execute(f"SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE '{DB_PREFIX}flows_%';")
        for tablename, in c.fetchall():
            m = re.match(f'^{DB_PREFIX}flows_([0-9]+)$', tablename)
            if not m:
                log.warning(f"MAINT: Table {tablename} does not match regex, skipping")
                continue
            day_seq = int(m.group(1))
            if day_seq > today_seq:
                log.warning(f"MAINT: CAREFUL! Table {tablename} marks a future day (today is {today_seq}); this should never happen! Skipping.")
                continue
            if day_seq < today_seq - LEAVE_N_PAST_PARTITIONS:
                log.info(f"MAINT: Removing old data: {tablename} (today is {today_seq})")
                c.execute(f"DROP TABLE {tablename};")
            else:
                log.info(f"MAINT: Leaving {tablename} (today is {today_seq})")
    log.info("MAINT: Maintenance finished.")


class NetFlowBot(Collector):

    def jobs(self):
        # remove old partitions:
        job_id = 'maint/remove_old_data'
        yield job_id, [3600], job_maint_remove_old_partitions, {}, 50

        # first merge together entity infos so that those entities from the same account are together:
        accounts_infos = defaultdict(list)
        for entity_info in self.fetch_job_configs('netflow'):
            accounts_infos[entity_info["account_id"]].append(entity_info)

        for account_id, entities_infos in accounts_infos.items():
            for interval_label, interval, first_run_ts in NETFLOW_AGGREGATION_INTERVALS:
                job_id = f'aggr/{interval_label}/{account_id}'
                job_params = {
                    "job_id": job_id,
                    "interval_label": interval_label,
                    "account_id": account_id,
                    "entities_infos": entities_infos,
                    "backend_url": self.backend_url,
                    "bot_token": self.bot_token,
                }
                start_ts = int(time.time()) + first_run_ts - interval  # start_ts must be in the past
                yield job_id, [interval], NetFlowBot.perform_account_aggr_job, job_params, start_ts


    @staticmethod
    def perform_account_aggr_job(*args, **job_params):
        # \d netflow_flows
        #      Column     |     Type      | Description
        #  ---------------+---------------+------------
        #   ts            | numeric(16,6) | UNIX timestamp
        #   client_ip     | inet          | entity IP address
        #   in_bytes      | integer       | number of bytes associated with an IP Flow
        #   protocol      | smallint      | IP protocol (see lookup.py -> PROTOCOLS)
        #   direction     | smallint      | flow direction: 0 - ingress flow, 1 - egress flow
        #   l4_dst_port   | integer       | destination port
        #   l4_src_port   | integer       | source port
        #   input_snmp    | smallint      | input interface index
        #   output_snmp   | smallint      | output interface index
        #   ipv4_dst_addr | inet          | source IP
        #   ipv4_src_addr | inet          | destination IP

        job_id = job_params["job_id"]
        interval_label = job_params["interval_label"]
        account_id = job_params["account_id"]
        entities = [(entity_info["entity_id"], entity_info["details"]["ipv4"],) for entity_info in job_params["entities_infos"]]
        log.info(f"Starting {interval_label} aggregation job for account {account_id}...")

        last_used_ts = _get_last_used_ts(job_id)
        max_ts = _get_current_max_ts()
        if max_ts is None or last_used_ts == max_ts:
            log.info(f"No netflow data found for job {job_id}, skipping.")
            return
        _save_current_max_ts(job_id, max_ts)
        if last_used_ts is None:
            log.info(f"Counter was not yet initialized for job {job_id}, skipping.")
            return
        #time_between = float(max_ts - last_used_ts)
        time_between = 1  # we want to use bytes as unit, not bytes per second

        # traffic:
        values = []
        sum_traffic_egress = 0
        sum_traffic_ingress = 0
        for entity_id, entity_ip in entities:
            v, s = NetFlowBot.get_traffic_for_entity(interval_label, last_used_ts, max_ts, time_between, DIRECTION_EGRESS, entity_id, entity_ip)
            values.extend(v)
            sum_traffic_egress += s
            v, s = NetFlowBot.get_traffic_for_entity(interval_label, last_used_ts, max_ts, time_between, DIRECTION_INGRESS, entity_id, entity_ip)
            values.extend(v)
            sum_traffic_ingress += s

        # cumulative sum for the whole account:
        output_path = NetFlowBot.construct_output_path_prefix(interval_label, DIRECTION_EGRESS, entity_id=None, interface=None)
        values.append({
            'p': output_path,
            'v': sum_traffic_egress / time_between,
        })
        output_path = NetFlowBot.construct_output_path_prefix(interval_label, DIRECTION_INGRESS, entity_id=None, interface=None)
        values.append({
            'p': output_path,
            'v': sum_traffic_ingress / time_between,
        })

        # top N IPs:
        for entity_id, entity_ip in entities:
            for direction in [DIRECTION_EGRESS, DIRECTION_INGRESS]:
                values.extend(NetFlowBot.get_top_N_IPs_for_entity(interval_label, last_used_ts, max_ts, time_between, direction, entity_id, entity_ip))
                values.extend(NetFlowBot.get_top_N_IPs_for_entity_interfaces(interval_label, last_used_ts, max_ts, time_between, direction, entity_id, entity_ip))
                values.extend(NetFlowBot.get_top_N_protocols_for_entity(interval_label, last_used_ts, max_ts, time_between, direction, entity_id, entity_ip))
                values.extend(NetFlowBot.get_top_N_protocols_for_entity_interfaces(interval_label, last_used_ts, max_ts, time_between, direction, entity_id, entity_ip))

        if not values:
            log.warning("No values found to be sent to Grafolean")
            return

        # send the data to Grafolean:
        send_results_to_grafolean(
            job_params['backend_url'],
            job_params['bot_token'],
            account_id,
            values,
        )


    @staticmethod
    def construct_output_path_prefix(interval_label, direction, entity_id, interface):
        prefix = f"netflow.{interval_label}.{'ingress' if direction == DIRECTION_INGRESS else 'egress'}"
        if entity_id is None:
            return prefix
        prefix = f'{prefix}.entity.{entity_id}'
        if interface is None:
            return prefix
        prefix = f'{prefix}.if.{interface}'
        return prefix


    @staticmethod
    @slow_down
    def get_traffic_for_entity(interval_label, last_used_ts, max_ts, time_between, direction, entity_id, entity_ip):
        # returns cumulative traffic for the whole entity, and traffic per interface for this entity
        with get_db_cursor() as c:

            c.execute(f"""
                SELECT
                    f.{'input_snmp' if direction == DIRECTION_INGRESS else 'output_snmp'},
                    sum(f.in_bytes)
                FROM
                    {DB_PREFIX}flows "f"
                WHERE
                    f.client_ip = %s AND
                    f.ts > %s AND
                    f.ts <= %s AND
                    f.direction = %s
                GROUP BY
                    f.{'input_snmp' if direction == DIRECTION_INGRESS else 'output_snmp'}
            """, (entity_ip, last_used_ts, max_ts, direction))

            values = []
            sum_traffic = 0
            for if_index, traffic_bytes in c.fetchall():
                output_path = NetFlowBot.construct_output_path_prefix(interval_label, direction, entity_id, interface=if_index)
                values.append({
                    'p': output_path,
                    'v': traffic_bytes / time_between,
                })
                sum_traffic += traffic_bytes

            output_path = NetFlowBot.construct_output_path_prefix(interval_label, direction, entity_id, interface=None)
            values.append({
                'p': output_path,
                'v': sum_traffic / time_between,
            })
            return values, sum_traffic


    @staticmethod
    @slow_down
    def get_top_N_IPs_for_entity_interfaces(interval_label, last_used_ts, max_ts, time_between, direction, entity_id, entity_ip):
        with get_db_cursor() as c, get_db_cursor() as c2:

            values = []
            c.execute(f"""
                SELECT
                    distinct(f.{'input_snmp' if direction == DIRECTION_INGRESS else 'output_snmp'}) "interface_index"
                FROM
                    {DB_PREFIX}flows "f"
                WHERE
                    f.client_ip = %s AND
                    f.ts > %s AND
                    f.ts <= %s AND
                    f.direction = %s
            """, (entity_ip, last_used_ts, max_ts, direction,))

            for interface_index, in c.fetchall():
                c2.execute(f"""
                    SELECT
                        f.{'ipv4_src_addr' if direction == DIRECTION_INGRESS else 'ipv4_dst_addr'},
                        sum(f.in_bytes) "traffic"
                    FROM
                        {DB_PREFIX}flows "f"
                    WHERE
                        f.client_ip = %s AND
                        f.ts > %s AND
                        f.ts <= %s AND
                        f.direction = %s AND
                        f.{'input_snmp' if direction == DIRECTION_INGRESS else 'output_snmp'} = %s
                    GROUP BY
                        f.{'ipv4_src_addr' if direction == DIRECTION_INGRESS else 'ipv4_dst_addr'}
                    ORDER BY
                        traffic desc
                    LIMIT {TOP_N_MAX};
                """, (entity_ip, last_used_ts, max_ts, direction, interface_index,))

                output_path_interface = NetFlowBot.construct_output_path_prefix(interval_label, direction, entity_id, interface=interface_index)
                for top_ip, traffic_bytes in c2.fetchall():
                    output_path = f"{output_path_interface}.topip.{path_part_encode(top_ip)}"
                    values.append({
                        'p': output_path,
                        'v': traffic_bytes / time_between,  # Bps
                    })

            return values

    @staticmethod
    @slow_down
    def get_top_N_IPs_for_entity(interval_label, last_used_ts, max_ts, time_between, direction, entity_id, entity_ip):
        with get_db_cursor() as c:
            values = []
            c.execute(f"""
                SELECT
                    f.{'ipv4_src_addr' if direction == DIRECTION_INGRESS else 'ipv4_dst_addr'},
                    sum(f.in_bytes) "traffic"
                FROM
                    {DB_PREFIX}flows "f"
                WHERE
                    f.client_ip = %s AND
                    f.ts > %s AND
                    f.ts <= %s AND
                    f.direction = %s
                GROUP BY
                    f.{'ipv4_src_addr' if direction == DIRECTION_INGRESS else 'ipv4_dst_addr'}
                ORDER BY
                    traffic desc
                LIMIT {TOP_N_MAX};
            """, (entity_ip, last_used_ts, max_ts, direction,))

            output_path_entity = NetFlowBot.construct_output_path_prefix(interval_label, direction, entity_id, interface=None)
            for top_ip, traffic_bytes in c.fetchall():
                output_path = f"{output_path_entity}.topip.{path_part_encode(top_ip)}"
                values.append({
                    'p': output_path,
                    'v': traffic_bytes / time_between,  # Bps
                })

            return values


    @staticmethod
    @slow_down
    def get_top_N_protocols_for_entity_interfaces(interval_label, last_used_ts, max_ts, time_between, direction, entity_id, entity_ip):
        with get_db_cursor() as c, get_db_cursor() as c2:

            values = []
            c.execute(f"""
                SELECT
                    distinct(f.{'input_snmp' if direction == DIRECTION_INGRESS else 'output_snmp'}) "interface_index"
                FROM
                    {DB_PREFIX}flows "f"
                WHERE
                    f.client_ip = %s AND
                    f.ts > %s AND
                    f.ts <= %s AND
                    f.direction = %s
            """, (entity_ip, last_used_ts, max_ts, direction,))

            for interface_index, in c.fetchall():
                c2.execute(f"""
                    SELECT
                        f.protocol,
                        sum(f.in_bytes) "traffic"
                    FROM
                        {DB_PREFIX}flows "f"
                    WHERE
                        f.client_ip = %s AND
                        f.ts > %s AND
                        f.ts <= %s AND
                        f.direction = %s AND
                        f.{'input_snmp' if direction == DIRECTION_INGRESS else 'output_snmp'} = %s
                    GROUP BY
                        f.protocol
                    ORDER BY
                        traffic desc
                    LIMIT {TOP_N_MAX};
                """, (entity_ip, last_used_ts, max_ts, direction, interface_index,))

                output_path_interface = NetFlowBot.construct_output_path_prefix(interval_label, direction, entity_id, interface=interface_index)
                for protocol, traffic_bytes in c2.fetchall():
                    output_path = f"{output_path_interface}.topprotocol.{path_part_encode(PROTOCOLS[protocol])}"
                    values.append({
                        'p': output_path,
                        'v': traffic_bytes / time_between,  # Bps
                    })

            return values

    @staticmethod
    @slow_down
    def get_top_N_protocols_for_entity(interval_label, last_used_ts, max_ts, time_between, direction, entity_id, entity_ip):
        with get_db_cursor() as c:
            values = []
            c.execute(f"""
                SELECT
                    f.protocol,
                    sum(f.in_bytes) "traffic"
                FROM
                    {DB_PREFIX}flows "f"
                WHERE
                    f.client_ip = %s AND
                    f.ts > %s AND
                    f.ts <= %s AND
                    f.direction = %s
                GROUP BY
                    f.protocol
                ORDER BY
                    traffic desc
                LIMIT {TOP_N_MAX};
            """, (entity_ip, last_used_ts, max_ts, direction,))

            output_path_entity = NetFlowBot.construct_output_path_prefix(interval_label, direction, entity_id, interface=None)
            for protocol, traffic_bytes in c.fetchall():
                output_path = f"{output_path_entity}.topprotocol.{path_part_encode(PROTOCOLS[protocol])}"
                values.append({
                    'p': output_path,
                    'v': traffic_bytes / time_between,  # Bps
                })

            return values

    # @staticmethod
    # @slow_down
    # def get_top_N_protocols(output_path_prefix, from_time, to_time, interface_index, is_direction_in=True):
    #     with get_db_cursor() as c:
    #         # TODO: missing check for IP: f.client_ip = %s AND
    #         c.execute(f"""
    #             SELECT
    #                 f.PROTOCOL,
    #                 sum(f.IN_BYTES) "traffic"
    #             FROM
    #                 {DB_PREFIX}flows "f"
    #             WHERE
    #                 f.ts >= %s AND
    #                 f.ts < %s AND
    #                 f.{'INPUT_SNMP' if is_direction_in else 'OUTPUT_SNMP'} = %s AND
    #                 f.DIRECTION = {'0' if is_direction_in else '1'}
    #             GROUP BY
    #                 f.PROTOCOL
    #             ORDER BY
    #                 traffic desc
    #             LIMIT 10;
    #         """, (from_time, to_time, interface_index,))

    #         values = []
    #         for protocol, traffic_bytes in c.fetchall():
    #             output_path = f"{output_path_prefix}.topproto.{'in' if is_direction_in else 'out'}.{interface_index}.if{interface_index}.{protocol}.{PROTOCOLS[protocol]}"
    #             values.append({
    #                 'p': output_path,
    #                 'v': traffic_bytes / 60.,  # Bps
    #             })
    #         return values


def wait_for_grafolean(backend_url):
    while True:
        url = '{}/status/info'.format(backend_url)
        log.info("Checking Grafolean status...")
        try:
            r = requests.get(url, timeout=10)
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
