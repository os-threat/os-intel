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

    def __init__(self,name:str,keys:list):
        self._engine = create_engine(f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
        self._name = name
        self._keys = keys
        self._schame = {}

    def init_local(self,df:pd.DataFrame,chunksize:int=1000,index:bool=False) ->int:
        # Drop old table and create new empty table
        total = df.to_sql(self._name, self._engine, if_exists='replace',
                          index=False, method="multi",
                          dtype=self._schema,chunksize=chunksize)
        return total

    @abstractmethod
    def pull_source(self,init:bool)->pd.DataFrame:
        pass

    def pull_local(self)->pd.DataFrame:
        df = pd.read_sql_table(self._name, self._engine)
        return df

    def log_table(self,df,n=5):
        table_ascii = tabulate(df.sample(n), headers='keys', tablefmt='psql')
        logger.info(f"\n{table_ascii}\n")

    @staticmethod
    def diff_tables(old_df:pd.DataFrame,new_df:pd.DataFrame,keys:list,columns:list):
        # sanity check like empty strings?
        old_df.set_index(keys,inplace=True)
        new_df.set_index(keys,inplace=True)

        logger.info(f'Prev is unique {old_df.index.is_unique}')
        logger.info(f'Curr is unique {new_df.index.is_unique}')

        merge_df = old_df[columns].join(new_df[columns], lsuffix='_old', rsuffix='_now',how='outer',on=keys)

        logger.info(f'Total merge {merge_df.shape[0]}')

        # IPs where the status has not changed
        same_df = merge_df[merge_df.status_old == merge_df.status_now]
        same_df['updated_at'] = pd.Timestamp.utcnow()
        added_df = merge_df[(merge_df.status_old==None) & (merge_df.status_now!=None)]
        removed_df = merge_df[(merge_df.status_old != None) & (merge_df.status_now == None)]

        table_ascii = tabulate(merge_df.sample(10), headers='keys', tablefmt='psql')

        logger.info(f"\n{table_ascii}\n")
        return same_df,added_df,removed_df


    def local_update(self,df,primary_key, column):
      md = MetaData(self._engine)
      table = Table(self._name, md, autoload=True)
      session = sessionmaker(bind=self._engine)()
      for index, row in df.iterrows():
        session.query(table).filter(table.columns[primary_key] == index).update({column: row[column]})
      session.commit()

class Ipv4Phishing(FileSource):
    _schema = {'ipv4': String(), 'status': String(), 'created_at': DateTime(), 'updated_at': DateTime(),
                     'deleted_at': DateTime()}

    def pull_source(self,init=DB_INIT) ->pd.DataFrame:
        '''
        An IP address can have multiple states according to their sources
        :param init:
        :return:
        '''
        rows = []
        poll_time = pd.Timestamp.utcnow()
        for status in ['ACTIVE', 'INACTIVE', 'INVALID']:
            logger.info(f'IP {status}')
            r = requests.get(f"{ROOT_URL}/phishing-IPs-{status}.txt")

            if r.status_code == 200:
                for line in r.content.decode().split('\n'):
                    ipstr = line.strip()

                    if len(ipstr) > 0 \
                            and validators.ip_address.ipv4(ipstr):
                        row = {'ipv4': ipstr, 'status': status}
                        rows.append(row)

        # compose data frame
        df = pd.DataFrame(rows)
        # add time stamps
        df['created_at'] = poll_time
        df['updated_at'] = None
        df['deleted_at'] = None
        # remove duplicates
        df.drop_duplicates(subset=self._keys,keep='last',inplace=True)
        logger.info(f'Pulled {df.shape[0]} IPV4 strings')

        if init:
            total = self.init_local(df)
            logger.info(f'Loaded {total} IPV4 strings')

        return df

class Ipv6Phishing(FileSource):
    _schema = {'ipv6': String(), 'status': String(), 'created_at': DateTime(), 'updated_at': DateTime(),
                     'deleted_at': DateTime()}

    def pull_source(self,init=DB_INIT) ->pd.DataFrame:
        '''
        An IP address can have multiple states according to their sources
        :param init:
        :return:
        '''
        rows = []
        poll_time = pd.Timestamp.utcnow()
        for status in ['ACTIVE', 'INACTIVE', 'INVALID']:
            logger.info(f'IP {status}')
            r = requests.get(f"{ROOT_URL}/phishing-IPs-{status}.txt")

            if r.status_code == 200:
                for line in r.content.decode().split('\n'):
                    ipstr = line.strip()

                    if len(ipstr) > 0 \
                            and validators.ip_address.ipv6(ipstr):
                        row = {'ipv4': ipstr, 'status': status}
                        rows.append(row)

        # compose data frame
        df = pd.DataFrame(rows)
        # add time stamps
        df['created_at'] = poll_time
        df['updated_at'] = None
        df['deleted_at'] = None
        # remove duplicates
        df.drop_duplicates(subset=self._keys,keep='last',inplace=True)
        logger.info(f'Pulled {df.shape[0]} IPV6 strings')

        if init:
            total = self.init_local(df)
            logger.info(f'Loaded {total} IPV6 strings')

        return df

source1 = Ipv4Phishing(name='phishing_database_ipv4',keys=['ipv4'])
old_df = source1.pull_source()
new_df = source1.pull_local()

(same_df,added_df,removed_df) = FileSource.diff_tables(old_df,new_df,keys=['ipv4'],columns=['status'])

logger.info(f'Identical {same_df.shape[0]}')
logger.info(f'Added {added_df.shape[0]}')
logger.info(f'Removed {removed_df.shape[0]}')

source2 = Ipv6Phishing(name='phishing_database_ipv6',keys=['ipv6'])
source2.pull_source()