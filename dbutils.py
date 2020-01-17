from colors import color
from contextlib import contextmanager
import logging
import os
import sys
import copy
import json

import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT, register_adapter
from psycopg2.extras import Json

logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logging.addLevelName(logging.DEBUG, color("DBG", 7))
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, color('WRN', fg='red'))
logging.addLevelName(logging.ERROR, color('ERR', bg='red'))
log = logging.getLogger("{}.{}".format(__name__, "base"))


db_pool = None
DB_PREFIX = 'netflow_'
register_adapter(dict, Json)


# https://medium.com/@thegavrikstory/manage-raw-database-connection-pool-in-flask-b11e50cbad3
@contextmanager
def get_db_connection():
    global db_pool
    try:
        conn = db_pool.getconn()
        conn.autocommit = True
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        yield conn
    finally:
        db_pool.putconn(conn)


@contextmanager
def get_db_cursor(commit=False):
    with get_db_connection() as connection:
      cursor = connection.cursor()
      try:
          yield cursor
          if commit:
              connection.commit()
      finally:
          cursor.close()


def db_connect():
    global db_pool
    host, dbname, user, password, connect_timeout = (
        os.environ.get('DB_HOST', 'localhost'),
        os.environ.get('DB_DATABASE', 'grafolean'),
        os.environ.get('DB_USERNAME', 'admin'),
        os.environ.get('DB_PASSWORD', 'admin'),
        int(os.environ.get('DB_CONNECT_TIMEOUT', '10'))
    )
    try:
        log.info("Connecting to database, host: [{}], db: [{}], user: [{}]".format(host, dbname, user))
        db_pool = ThreadedConnectionPool(1, 20,
                              database=dbname,
                              user=user,
                              password=password,
                              host=host,
                              port=5432,
                              connect_timeout=connect_timeout)
    except:
        db_pool = None
        log.error("DB connection failed")

db_connect()

# This class is only needed until we replace all db.cursor() calls with get_db_cursor()
class ThinDBWrapper(object):
    @staticmethod
    def cursor():
        return get_db_cursor()
db = ThinDBWrapper


###########################
#   DB schema migration   #
###########################

def get_existing_schema_version():
    existing_schema_version = 0
    with db.cursor() as c:
        try:
            c.execute(f'SELECT schema_version FROM {DB_PREFIX}runtime_data;')
            res = c.fetchone()
            existing_schema_version = res[0]
        except psycopg2.ProgrammingError:
            pass
    return existing_schema_version


def _get_migration_method(next_migration_version):
    method_name = 'migration_step_{}'.format(next_migration_version)
    return method_name if hasattr(sys.modules[__name__], method_name) else None


def is_migration_needed():
    existing_schema_version = get_existing_schema_version()
    return _get_migration_method(existing_schema_version + 1) is not None


def migrate_if_needed():
    existing_schema_version = get_existing_schema_version()
    try_migrating_to = existing_schema_version + 1
    while True:
        method_name = _get_migration_method(try_migrating_to)
        if method_name is None:
            break
        log.info("Migrating DB schema from {} to {}".format(existing_schema_version, try_migrating_to))
        method_to_call = getattr(sys.modules[__name__], method_name)
        method_to_call()
        # automatically upgrade schema version if there is no exception:
        with db.cursor() as c:
            c.execute(f'UPDATE {DB_PREFIX}runtime_data SET schema_version = %s;', (try_migrating_to,))
        try_migrating_to += 1
    if try_migrating_to == existing_schema_version + 1:
        return False  # migration wasn't meeded
    else:
        return True


def migration_step_1():
    with db.cursor() as c:
        c.execute(f'CREATE TABLE {DB_PREFIX}runtime_data (schema_version SMALLSERIAL NOT NULL);')
        c.execute(f'INSERT INTO {DB_PREFIX}runtime_data (schema_version) VALUES (1);')

def migration_step_2():
    with db.cursor() as c:
        c.execute(f'CREATE TABLE {DB_PREFIX}flows (seq BIGSERIAL NOT NULL PRIMARY KEY, version SMALLSERIAL NOT NULL, client TEXT, ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, data JSONB NOT NULL);')

