import argparse
import gzip
import json
import logging
import os
import sys
import time
from collections import defaultdict

from colors import color
import dotenv
import redis
import requests

from grafoleancollector import Collector, send_results_to_grafolean
from lookup import PROTOCOLS, DB_PREFIX

logging.basicConfig(format='%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "base"))


REDIS_HOST = os.environ.get('REDIS_HOST', '127.0.0.1')
r = redis.Redis(host=REDIS_HOST)


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
        job_id = 'traffic_per_protocol'
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
        traffic_per_protocol = r.hgetall(f'{DB_PREFIX}traffic_per_protocol')
        entity_info = job_params["entity_info"]
        values = []
        now = time.time()
        for protocol, traffic_counter in traffic_per_protocol.items():
            output_path = f'entity.{entity_info["entity_id"]}.netflow.traffic_per_protocol.{protocol.decode("utf-8")}'

            # since we are getting the counters, convert them to values:
            dv, dt = convert_counter_to_value(f'{DB_PREFIX}_counter_{output_path}', traffic_counter, now)
            if dv is None:
                continue
            values.append({
                'p': output_path,
                'v': dv / dt,
            })

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


def _get_previous_counter_value(counter_ident):
    prev_value = r.hgetall(counter_ident)
    if not prev_value:  # empty dict
        return None, None
    return int(prev_value[b'v']), float(prev_value[b't'])


def _save_current_counter_value(new_value, now, counter_ident):
    r.hmset(counter_ident, {b'v': new_value, b't': now})


def convert_counter_to_value(counter_ident, new_value, now):
    old_value, t = _get_previous_counter_value(counter_ident)
    new_value = int(float(new_value))
    _save_current_counter_value(new_value, now, counter_ident)
    if old_value is None:
        # no previous counter, can't calculate value:
        log.debug(f"Counter {counter_ident} has no previous value.")
        return None, None
    if new_value < old_value:
        # new counter value is lower than the old one, probably overflow: (or reset)
        log.warning(f"Counter overflow detected for counter {counter_ident}, discarding value - if this happens often, consider decreasing polling interval.")
        return None, None
    dt = now - t
    dv = new_value - old_value
    return dv, dt


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
