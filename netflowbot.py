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
from dbutils import get_db_cursor, DB_PREFIX
from lookup import PROTOCOLS, DIRECTION_INGRESS, DIRECTION_EGRESS

logging.basicConfig(format='%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "bot"))


NETFLOW_AGGREGATION_INTERVALS = [
    ('1min', 60),
    ('15min', 15 * 60),
    ('1h', 3600),
    ('4h', 4 * 3600),
    ('24h', 24 * 3600),
]
TOP_N_MAX = 10


def path_part_encode(s):
    return s.replace(".", '%2e')


def _get_last_used_seq(job_id):
    with get_db_cursor() as c:
        c.execute(f'SELECT j.last_used_seq, r.ts FROM {DB_PREFIX}bot_jobs j, {DB_PREFIX}records r WHERE j.job_id = %s AND j.last_used_seq = r.seq;', (job_id,))
        rec = c.fetchone()
        if rec is None:
            return None, None
        last_used_seq, ts = rec
        return last_used_seq, ts

def _get_current_max_seq():
    with get_db_cursor() as c:
        c.execute(f"SELECT seq, ts FROM {DB_PREFIX}records WHERE seq = (SELECT MAX(seq) FROM {DB_PREFIX}records);")
        rec = c.fetchone()
        if rec is None:
            return None, None
        max_seq, now_ts = rec
        return max_seq, now_ts

def _save_current_max_seq(job_id, seq):
    with get_db_cursor() as c:
        c.execute(f"INSERT INTO {DB_PREFIX}bot_jobs (job_id, last_used_seq) VALUES (%s, %s) ON CONFLICT (job_id) DO UPDATE SET last_used_seq = %s;", (job_id, seq, seq))


class NetFlowBot(Collector):

    def jobs(self):
        # first merge together entity infos so that those entities from the same account are together:
        accounts_infos = defaultdict(list)
        for entity_info in self.fetch_job_configs('netflow'):
            accounts_infos[entity_info["account_id"]].append(entity_info)

        for account_id, entities_infos in accounts_infos.items():
            for interval_label, interval in NETFLOW_AGGREGATION_INTERVALS:
                job_id = f'aggr/{interval_label}/{account_id}'
                job_params = {
                    "job_id": job_id,
                    "interval_label": interval_label,
                    "account_id": account_id,
                    "entities_infos": entities_infos,
                    "backend_url": self.backend_url,
                    "bot_token": self.bot_token,
                }
                yield job_id, [interval], NetFlowBot.perform_account_aggr_job, job_params


    @staticmethod
    def perform_account_aggr_job(*args, **job_params):
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
        interval_label = job_params["interval_label"]
        account_id = job_params["account_id"]
        entities = [(entity_info["entity_id"], entity_info["details"]["ipv4"],) for entity_info in job_params["entities_infos"]]


        last_used_seq, last_used_ts = _get_last_used_seq(job_id)
        max_seq, max_ts = _get_current_max_seq()
        if max_seq is None or last_used_ts == max_ts:
            log.info(f"No netflow data found for job {job_id}, skipping.")
            return
        _save_current_max_seq(job_id, max_seq)
        if last_used_seq is None:
            log.info(f"Counter was not yet initialized for job {job_id}, skipping.")
            return
        time_between = float(max_ts - last_used_ts)

        # traffic:
        values = []
        sum_traffic_egress = 0
        sum_traffic_ingress = 0
        for entity_id, entity_ip in entities:
            v, s = NetFlowBot.get_traffic_for_entity(interval_label, last_used_seq, max_seq, time_between, DIRECTION_EGRESS, entity_id, entity_ip)
            values.extend(v)
            sum_traffic_egress += s
            v, s = NetFlowBot.get_traffic_for_entity(interval_label, last_used_seq, max_seq, time_between, DIRECTION_INGRESS, entity_id, entity_ip)
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
                values.extend(NetFlowBot.get_top_N_IPs_for_entity(interval_label, last_used_seq, max_seq, time_between, direction, entity_id, entity_ip))
                values.extend(NetFlowBot.get_top_N_IPs_for_entity_interfaces(interval_label, last_used_seq, max_seq, time_between, direction, entity_id, entity_ip))
                values.extend(NetFlowBot.get_top_N_protocols_for_entity(interval_label, last_used_seq, max_seq, time_between, direction, entity_id, entity_ip))
                values.extend(NetFlowBot.get_top_N_protocols_for_entity_interfaces(interval_label, last_used_seq, max_seq, time_between, direction, entity_id, entity_ip))

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

        # protocol_str = 'TCP'
        # ipv4_dst_addr = '1.2.3.4'
        # ipv4_src_addr = '4.3.2.1'
        # # traffic on all devices, all interfaces, per ingress / egress:
        # f'netflow.{interval_label}.egress'
        # f'netflow.{interval_label}.ingress'
        # # traffic on all devices, all interfaces, per ingress / egress, for top X protocols:
        # f'netflow.{interval_label}.egress.protocol.{protocol_str}'
        # f'netflow.{interval_label}.ingress.protocol.{protocol_str}'
        # # traffic on all devices, all interfaces, per ingress / egress, for top X ips:
        # f'netflow.{interval_label}.egress.ip.{ipv4_dst_addr}'
        # f'netflow.{interval_label}.ingress.ip.{ipv4_src_addr}'

        # # traffic on all interfaces, per device, per ingress / egress:
        # f'netflow.{interval_label}.egress.entity.{entity_id}'
        # f'netflow.{interval_label}.ingress.entity.{entity_id}'
        # # traffic on all interfaces, per device, per ingress / egress, for top X protocols:
        # f'netflow.{interval_label}.egress.entity.{entity_id}.protocol.{protocol_str}'
        # f'netflow.{interval_label}.ingress.entity.{entity_id}.protocol.{protocol_str}'
        # # traffic on all interfaces, per device, per ingress / egress, for top X ips:
        # f'netflow.{interval_label}.egress.entity.{entity_id}.ip.{ipv4_dst_addr}'
        # f'netflow.{interval_label}.ingress.entity.{entity_id}.ip.{ipv4_src_addr}'

        # # traffic per interface, per device, per ingress / egress:
        # f'netflow.{interval_label}.egress.entity.{entity_id}.if.{output_snmp}'
        # f'netflow.{interval_label}.ingress.entity.{entity_id}.if.{input_snmp}'
        # # traffic per interface, per device, per ingress / egress, for top X protocols:
        # f'netflow.{interval_label}.egress.entity.{entity_id}.if.{output_snmp}.protocol.{protocol_str}'
        # f'netflow.{interval_label}.ingress.entity.{entity_id}.if.{input_snmp}.protocol.{protocol_str}'
        # # traffic per interface, per device, per ingress / egress, for top X ips:
        # f'netflow.{interval_label}.egress.entity.{entity_id}.if.{output_snmp}.ip.{ipv4_dst_addr}'
        # f'netflow.{interval_label}.ingress.entity.{entity_id}.if.{input_snmp}.ip.{ipv4_src_addr}'


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
    def get_traffic_for_entity(interval_label, last_seq, max_seq, time_between, direction, entity_id, entity_ip):
        # returns cumulative traffic for the whole entity, and traffic per interface for this entity
        with get_db_cursor() as c:

            c.execute(f"""
                SELECT
                    f.{'input_snmp' if direction == DIRECTION_INGRESS else 'output_snmp'},
                    sum(f.in_bytes)
                FROM
                    {DB_PREFIX}records "r",
                    {DB_PREFIX}flows "f"
                WHERE
                    r.client_ip = %s AND
                    r.seq > %s AND
                    r.seq <= %s AND
                    r.seq = f.record AND
                    f.direction = %s
                GROUP BY
                    f.{'input_snmp' if direction == DIRECTION_INGRESS else 'output_snmp'}
            """, (entity_ip, last_seq, max_seq, direction))

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
    def get_top_N_IPs_for_entity_interfaces(interval_label, last_seq, max_seq, time_between, direction, entity_id, entity_ip):
        with get_db_cursor() as c, get_db_cursor() as c2:

            values = []
            c.execute(f"""
                SELECT
                    distinct(f.{'input_snmp' if direction == DIRECTION_INGRESS else 'output_snmp'}) "interface_index"
                FROM
                    netflow_records "r",
                    netflow_flows "f"
                WHERE
                    r.client_ip = %s AND
                    r.seq > %s AND
                    r.seq <= %s AND
                    r.seq = f.record AND
                    f.direction = %s
            """, (entity_ip, last_seq, max_seq, direction,))

            for interface_index, in c.fetchall():
                c2.execute(f"""
                    SELECT
                        f.{'ipv4_src_addr' if direction == DIRECTION_INGRESS else 'ipv4_dst_addr'},
                        sum(f.in_bytes) "traffic"
                    FROM
                        netflow_records "r",
                        netflow_flows "f"
                    WHERE
                        r.client_ip = %s AND
                        r.seq > %s AND
                        r.seq <= %s AND
                        r.seq = f.record AND
                        f.direction = %s AND
                        f.{'input_snmp' if direction == DIRECTION_INGRESS else 'output_snmp'} = %s
                    GROUP BY
                        f.{'ipv4_src_addr' if direction == DIRECTION_INGRESS else 'ipv4_dst_addr'}
                    ORDER BY
                        traffic desc
                    LIMIT {TOP_N_MAX};
                """, (entity_ip, last_seq, max_seq, direction, interface_index,))

                output_path_interface = NetFlowBot.construct_output_path_prefix(interval_label, direction, entity_id, interface=interface_index)
                for top_ip, traffic_bytes in c2.fetchall():
                    output_path = f"{output_path_interface}.topip.{path_part_encode(top_ip)}"
                    values.append({
                        'p': output_path,
                        'v': traffic_bytes / time_between,  # Bps
                    })

            return values

    @staticmethod
    def get_top_N_IPs_for_entity(interval_label, last_seq, max_seq, time_between, direction, entity_id, entity_ip):
        with get_db_cursor() as c:
            values = []
            c.execute(f"""
                SELECT
                    f.{'ipv4_src_addr' if direction == DIRECTION_INGRESS else 'ipv4_dst_addr'},
                    sum(f.in_bytes) "traffic"
                FROM
                    netflow_records "r",
                    netflow_flows "f"
                WHERE
                    r.client_ip = %s AND
                    r.seq > %s AND
                    r.seq <= %s AND
                    r.seq = f.record AND
                    f.direction = %s
                GROUP BY
                    f.{'ipv4_src_addr' if direction == DIRECTION_INGRESS else 'ipv4_dst_addr'}
                ORDER BY
                    traffic desc
                LIMIT {TOP_N_MAX};
            """, (entity_ip, last_seq, max_seq, direction,))

            output_path_entity = NetFlowBot.construct_output_path_prefix(interval_label, direction, entity_id, interface=None)
            for top_ip, traffic_bytes in c.fetchall():
                output_path = f"{output_path_entity}.topip.{path_part_encode(top_ip)}"
                values.append({
                    'p': output_path,
                    'v': traffic_bytes / time_between,  # Bps
                })

            return values


    @staticmethod
    def get_top_N_protocols_for_entity_interfaces(interval_label, last_seq, max_seq, time_between, direction, entity_id, entity_ip):
        with get_db_cursor() as c, get_db_cursor() as c2:

            values = []
            c.execute(f"""
                SELECT
                    distinct(f.{'input_snmp' if direction == DIRECTION_INGRESS else 'output_snmp'}) "interface_index"
                FROM
                    netflow_records "r",
                    netflow_flows "f"
                WHERE
                    r.client_ip = %s AND
                    r.seq > %s AND
                    r.seq <= %s AND
                    r.seq = f.record AND
                    f.direction = %s
            """, (entity_ip, last_seq, max_seq, direction,))

            for interface_index, in c.fetchall():
                c2.execute(f"""
                    SELECT
                        f.protocol,
                        sum(f.in_bytes) "traffic"
                    FROM
                        netflow_records "r",
                        netflow_flows "f"
                    WHERE
                        r.client_ip = %s AND
                        r.seq > %s AND
                        r.seq <= %s AND
                        r.seq = f.record AND
                        f.direction = %s AND
                        f.{'input_snmp' if direction == DIRECTION_INGRESS else 'output_snmp'} = %s
                    GROUP BY
                        f.protocol
                    ORDER BY
                        traffic desc
                    LIMIT {TOP_N_MAX};
                """, (entity_ip, last_seq, max_seq, direction, interface_index,))

                output_path_interface = NetFlowBot.construct_output_path_prefix(interval_label, direction, entity_id, interface=interface_index)
                for protocol, traffic_bytes in c2.fetchall():
                    output_path = f"{output_path_interface}.topprotocol.{path_part_encode(PROTOCOLS[protocol])}"
                    values.append({
                        'p': output_path,
                        'v': traffic_bytes / time_between,  # Bps
                    })

            return values

    @staticmethod
    def get_top_N_protocols_for_entity(interval_label, last_seq, max_seq, time_between, direction, entity_id, entity_ip):
        with get_db_cursor() as c:
            values = []
            c.execute(f"""
                SELECT
                    f.protocol,
                    sum(f.in_bytes) "traffic"
                FROM
                    netflow_records "r",
                    netflow_flows "f"
                WHERE
                    r.client_ip = %s AND
                    r.seq > %s AND
                    r.seq <= %s AND
                    r.seq = f.record AND
                    f.direction = %s
                GROUP BY
                    f.protocol
                ORDER BY
                    traffic desc
                LIMIT {TOP_N_MAX};
            """, (entity_ip, last_seq, max_seq, direction,))

            output_path_entity = NetFlowBot.construct_output_path_prefix(interval_label, direction, entity_id, interface=None)
            for protocol, traffic_bytes in c.fetchall():
                output_path = f"{output_path_entity}.topprotocol.{path_part_encode(PROTOCOLS[protocol])}"
                values.append({
                    'p': output_path,
                    'v': traffic_bytes / time_between,  # Bps
                })

            return values

    # @staticmethod
    # def get_top_N_protocols(output_path_prefix, from_time, to_time, interface_index, is_direction_in=True):
    #     with get_db_cursor() as c:
    #         # TODO: missing check for IP: r.client_ip = %s AND
    #         c.execute(f"""
    #             SELECT
    #                 f.PROTOCOL,
    #                 sum(f.IN_BYTES) "traffic"
    #             FROM
    #                 netflow_records "r",
    #                 netflow_flows "f"
    #             WHERE
    #                 r.ts >= %s AND
    #                 r.ts < %s AND
    #                 r.seq = f.record AND
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
