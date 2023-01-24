import os
from sqlalchemy.types import Integer,String,DateTime
import pandas as pd
import requests
import ipaddress
import validators
from stix2 import Bundle, Identity, Indicator, IPv4Address,IPv6Address, Relationship, DomainName, URL
from sqlalchemy import create_engine
import psycopg2
from tabulate import tabulate

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

ROOT_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master'

DB_USER = os.getenv('DB_USER','admin')
DB_PASSWORD = os.getenv('DB_PASSWORD','admin')
DB_HOST = os.getenv('DB_HOST','localhost')
DB_PORT = os.getenv('DB_PORT','5432')
DB_NAME = os.getenv('DB_NAME',default="fastapi")
DB_INIT = os.getenv('DB_INIT',default="false")
#DB_INIT = os.getenv('DB_INIT',default="true")

engine = create_engine(f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}")

def url_phishing_to_df()->pd.DataFrame:
    rows = []
    for status in ['ACTIVE', 'INACTIVE', 'INVALID']:
        logger.info(f'IP {status}')
        r = requests.get(f"{ROOT_URL}/phishing-IPs-{status}.txt")

        if r.status_code == 200:
            total = 0
            for line in r.content.decode().split('\n'):
                ipstr = line.strip()

                if len(ipstr) > 0:
                    if validators.ip_address.ipv4(ipstr):
                        row = {'ipv4':ipstr,'status':status}
                    if validators.ip_address.ipv6(ipstr):
                        row = {'ipv6':ipstr,'status':status}
                    row['created_at'] = pd.Timestamp.utcnow()
                    row['updated_at'] = None
                    row['deleted_at'] = None

                    rows.append(row)
    return pd.DataFrame(rows)

def init_database(df):
    col_types = {'ipv4':String(),'status':String(),'created_at':DateTime(),'updated_at':DateTime(),'deleted_at':DateTime()}
    # Drop old table and create new empty table
    total = df.to_sql('phishing_database', engine, if_exists='replace', index=False,method='multi',chunksize=100,dtype=col_types)
    return total


def print_table(df,n=5):
    table_ascii = tabulate(df.sample(n), headers='keys', tablefmt='psql')
    logger.info(f"\n{table_ascii}\n")

def diff_tables(prev_df,curr_df):
    # sanity check like empty strings?
    prev_df.set_index('ipv4',inplace=True)
    curr_df.set_index('ipv4',inplace=True)

    logger.info(f'Prev is unique {prev_df.index.is_unique}')
    logger.info(f'Curr is unique {curr_df.index.is_unique}')
    state_cols = ['status']
    merge_df = prev_df[state_cols].join(curr_df[state_cols], lsuffix='_old', rsuffix='_now',how='outer',on='ipv4')

    logger.info(f'Total merge {merge_df.shape[0]}')
    table_ascii = tabulate(merge_df.sample(10), headers='keys', tablefmt='psql')
    # filter the identical rows....
    same_df = merge_df[merge_df.status_old == merge_df.status_now]
    logger.info(f"\n{table_ascii}\n")
    return same_df

if DB_INIT=='true':
    current_df = url_phishing_to_df()
    totals = init_database(current_df)
    logger.info(f'Total entities {totals}')
else:
    current_df = url_phishing_to_df()
    previous_df = pd.read_sql_table('phishing_database',engine)
    (same_df) = diff_tables(previous_df,current_df)
    logger.info(f'Total previous entities {previous_df.shape[0]}')
    logger.info(f'Total current entities {current_df.shape[0]}')
    logger.info(f'Unchanged {same_df.shape[0]}')
    print_table(current_df)