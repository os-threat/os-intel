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
from sqlalchemy import MetaData,Table
from sqlalchemy.orm import sessionmaker
from abc import ABC, abstractmethod
from distutils.util import strtobool

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


DB_USER = os.getenv('DB_USER','admin')
DB_PASSWORD = os.getenv('DB_PASSWORD','admin')
DB_HOST = os.getenv('DB_HOST','localhost')
DB_PORT = os.getenv('DB_PORT','5432')
DB_NAME = os.getenv('DB_NAME',default="fastapi")
DB_INIT = strtobool(os.getenv('DB_INIT',default="false"))
#DB_INIT = os.getenv('DB_INIT',default="true")
ROOT_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master'

class FileSource():

    def __init__(self,name:str):
        self._engine = create_engine(f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
        self._name = name
        self._schame = {}

    def init_local(self,df) ->int:
        # Drop old table and create new empty table
        total = df.to_sql(self._name, self._engine, if_exists='replace', index=False, dtype=self._schema)
        return total

    @abstractmethod
    def pull_source(self,init:bool)->pd.DataFrame:
        pass

    @abstractmethod
    def pull_local(self)->pd.DataFrame:
        pass

    def log_table(self,df,n=5):
        table_ascii = tabulate(df.sample(n), headers='keys', tablefmt='psql')
        logger.info(f"\n{table_ascii}\n")

class Ipv4Phishing(FileSource):
    _schema = {'ipv4': String(), 'status': String(), 'created_at': DateTime(), 'updated_at': DateTime(),
                     'deleted_at': DateTime()}

    def pull_source(self,init=DB_INIT) ->pd.DataFrame:
        rows = []
        for status in ['ACTIVE', 'INACTIVE', 'INVALID']:
            logger.info(f'IP {status}')
            r = requests.get(f"{ROOT_URL}/phishing-IPs-{status}.txt")

            if r.status_code == 200:
                for line in r.content.decode().split('\n'):
                    ipstr = line.strip()

                    if len(ipstr) > 0:
                        if validators.ip_address.ipv4(ipstr):
                            row = {'ipv4': ipstr, 'status': status}
                            row['created_at'] = pd.Timestamp.utcnow()
                            row['updated_at'] = None
                            row['deleted_at'] = None
                            rows.append(row)
                        else:
                            continue
        # deduplicate
        df = pd.DataFrame(rows)
        df.drop_duplicates(subset=['ipv4', 'status'], keep='last', inplace=True)
        if init:
            total = self.init_local(df)
            logger.info(f'Loaded {total} IPV4 strings')
        logger.info(f'Pulled {df.shape[0]} IPV4 strings')
        return df

class Ipv6Phishing(FileSource):
    _schema = {'ipv6': String(), 'status': String(), 'created_at': DateTime(), 'updated_at': DateTime(),
                     'deleted_at': DateTime()}

    def pull_source(self,init=DB_INIT) ->pd.DataFrame:
        rows = []
        for status in ['ACTIVE', 'INACTIVE', 'INVALID']:
            logger.info(f'IP {status}')
            r = requests.get(f"{ROOT_URL}/phishing-IPs-{status}.txt")

            if r.status_code == 200:
                for line in r.content.decode().split('\n'):
                    ipstr = line.strip()

                    if len(ipstr) > 0:
                        if validators.ip_address.ipv6(ipstr):
                            row = {'ipv6': ipstr, 'status': status}
                            row['created_at'] = pd.Timestamp.utcnow()
                            row['updated_at'] = None
                            row['deleted_at'] = None
                            rows.append(row)
                        else:
                            continue
        # deduplicate
        df = pd.DataFrame(rows)
        df.drop_duplicates(subset=['ipv6', 'status'], keep='last', inplace=True)
        if init:
            total = self.init_local(df)
            logger.info(f'Loaded {total} IPV6 strings')
        logger.info(f'Pulled {df.shape[0]} IPV6 strings')
        return df

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
    # IPs where the status has not changed
    same_df = merge_df[merge_df.status_old == merge_df.status_now]
    same_df['updated_at'] = pd.Timestamp.utcnow()
    added_df = merge_df[(merge_df.status_old==None) & (merge_df.status_now!=None)]
    removed_df = merge_df[(merge_df.status_old != None) & (merge_df.status_now == None)]

    logger.info(f"\n{table_ascii}\n")
    return same_df,added_df,removed_df

def dataframe_update(df, table, engine, primary_key, column):
  md = MetaData(engine)
  table = Table(table, md, autoload=True)
  session = sessionmaker(bind=engine)()
  for index, row in df.iterrows():
    session.query(table).filter(table.columns[primary_key] == index).update({column: row[column]})
  session.commit()

def old():
    if DB_INIT:
        current_df = url_phishing_to_df(filter='ipv4')
        totals = init_database(current_df,filter)
        logger.info(f'Total entities {totals}')
    else:
        current_df = url_phishing_to_df(filter='ipv4')
        previous_df = pd.read_sql_table('phishing_database_ipv4',engine)
        (same_df,added_df,removed_df) = diff_tables(previous_df,current_df)
        dataframe_update(same_df,'phishing_database_ipv4',engine,'ipv4','updated_at')
        logger.info(f'Previous entities {previous_df.shape[0]}')
        logger.info(f'Current entities {current_df.shape[0]}')
        logger.info(f'Identical {same_df.shape[0]}')
        logger.info(f'Added {added_df.shape[0]}')
        logger.info(f'Removed {removed_df.shape[0]}')
        print_table(same_df)

source1 = Ipv4Phishing(name='phishing_database_ipv4')
source1.pull_source()

source2 = Ipv6Phishing(name='phishing_database_ipv6')
source2.pull_source()