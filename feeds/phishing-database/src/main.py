import os

import requests
import ipaddress
import validators
from stix2 import Bundle, Identity, Indicator, IPv4Address,IPv6Address, Relationship, DomainName, URL, ObservedData
from stix2 import utils
from stix2.exceptions import InvalidValueError

from stixorm.module.typedb import TypeDBSink, TypeDBSource, get_embedded_match
from stixorm.module.authorise import authorised_mappings, import_type_factory
from stixorm.module.definitions.os_threat import Feed, Feeds, ThreatSubObject
from stixorm.module.typedb_lib.instructions import ResultStatus
from stix2.v21.common import ExternalReference,MarkingDefinition,StatementMarking

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# define the database data and import details
url_typedb = {
    "uri": os.getenv("TYPEDB_HOST","localhost"),
    "port": os.getenv("TYPEDB_PORT","1729"),
    "database": "stixorm",
    "user": None,
    "password": None
}

class Loader():
    ROOT_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master'

    def __init__(self,sink:TypeDBSink):
        self.author = Identity(
            name="Phishing Database",
            identity_class="organization",
        )

        self._sink = sink
    def add_IP_phish(self)->Feed:

        for status in ['ACTIVE','INACTIVE','INVALID']:
            logger.info(f'IP {status}')
            r = requests.get(f"{self.ROOT_URL}/phishing-IPs-{status}.txt")

            observedData = []
            sdos = []
            total = 0
            if r.status_code == 200:

                for line in r.content.decode().split('\n'):
                    ipstr = line.strip()

                    if len(ipstr)>0:
                        try:
                            if validators.ip_address.ipv4(ipstr):
                                sdo = IPv4Address(value=ipstr)

                                observation = ObservedData(
                                    first_observed=utils.get_timestamp(),
                                    last_observed=utils.get_timestamp(),
                                    number_observed=1,
                                    created_by_ref=self.author,
                                    object_refs=[sdo]
                                )

                                observedData.append(observation)
                                sdos.append(sdo)

                            elif validators.ip_address.ipv6(ipstr):
                                sdo = IPv6Address(value=ipstr)
                                observation = ObservedData(
                                    first_observed=utils.get_timestamp(),
                                    last_observed=utils.get_timestamp(),
                                    number_observed=1,
                                    created_by_ref=self.author,
                                    object_refs=[sdo]
                                )

                                observedData.append(observation)
                                sdos.append(sdo)

                        except Exception as e:
                            logger.error(e)

                subobs = []
                for sdo in sdos:
                    subobj = ThreatSubObject(
                        object_ref=sdo.id,
                        created=utils.get_timestamp(),
                        modified=utils.get_timestamp()
                    )

                    subobs.append(subobj)

                info = ExternalReference(source_name=f"Phishing Database {status}",
                                         external_id=f"phishing-IPs-{status}.txt",
                                         url="https://github.com/mitchellkrogza/Phishing.Database/blob/master/phishing-IPs-ACTIVE.txt")

                marking_def_statement = MarkingDefinition(
                    id="marking-definition--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
                    created="2017-04-14T13:07:49.812Z",
                    definition_type="statement",
                    definition=StatementMarking("Copyright (c) Stark Industries 2017.")
                )

                a_feed = Feed(name='phishing-db',
                              description="the phishing database",
                              paid=False,
                              free=False,
                              created=utils.get_timestamp(),
                              labels=[],
                              lang="en",
                              external_references=[info],
                              object_marking_refs=[marking_def_statement],
                              contents=subobs)
                # logically let's put the correct order
                results= self._sink.add([info,marking_def_statement,sdos,observedData,subobs,a_feed])
                # check the progress....
            else:
                raise Exception('Feed URL is down')

    def get_domain_phish(self,add_indicators=False):

        observables = []
        indicators = []

        for status in ['ACTIVE','INACTIVE','INVALID']:
            logger.info(f'Domain {status}')
            r = requests.get(f"{self.ROOT_URL}/phishing-domains-{status}.txt")

            if r.status_code == 200:
                total = 0
                for line in r.content.decode().split('\n'):
                    domain = line.strip()
                    if len(domain)>0 and validators.domain(domain):
                        total+=1
                        observable = DomainName(value=domain)
                        observables.append(observable)
                        indicator = Indicator(
                            name=domain,
                            description="Phishing Domain",
                            created_by_ref=f"{self.author.id}",
                            pattern_type="stix",
                            pattern=f"[domain:value = '{domain}']",
                            labels=["phishing",status],
                        )
                        indicators.append(indicator)

            else:
                raise Exception('Feed URL is down')

        assert total>0

        feedObservation = ObservedData(
            first_observed=utils.get_timestamp(),
            last_observed=utils.get_timestamp(),
            number_observed=total,
            created_by_ref=self.author,
            object_refs= observables
        )

        if add_indicators:
            rels = []
            for indicator in indicators:
                rel = Relationship(indicator, 'based-on', feedObservation)
                rels.append(rel)
                return Bundle(self.author, feedObservation, observables, rels, indicators)
        else:
            return Bundle(self.author, feedObservation, observables)

    def get_links_phish(self,add_indicators=False):
        observables = []
        indicators = []

        for status in ['ACTIVE','INACTIVE','INVALID']:
            logger.info(f'URL {status}')
            r = requests.get(f"{self.ROOT_URL}/phishing-links-{status}.txt")

            if r.status_code == 200:
                total = 0
                for line in r.content.decode().split('\n'):
                    url = line.strip()
                    if len(url)>0 and validators.url(url):
                        total+=1
                        observable = URL(value=url)
                        observables.append(observable)

                        try:
                            indicator = Indicator(
                                name=url,
                                description="Phishing URL",
                                created_by_ref=f"{self.author.id}",
                                pattern_type="stix",
                                pattern=f"[url:value = '{url}']",
                                labels=["phishing",status],
                            )
                            indicators.append(indicator)
                        except InvalidValueError as ver:
                            logger.error(f'Invalid PATTERN for URL '
                                         f'{url}')
            else:
                raise Exception('Feed URL is down')

        assert total>0

        feedObservation = ObservedData(
            first_observed=utils.get_timestamp(),
            last_observed=utils.get_timestamp(),
            number_observed=total,
            created_by_ref=self.author,
            object_refs= observables
        )

        if add_indicators:
            rels = []
            for indicator in indicators:
                rel = Relationship(indicator, 'based-on', feedObservation)
                rels.append(rel)
                return Bundle(self.author, feedObservation, observables, rels, indicators)
        else:
            return Bundle(self.author, feedObservation, observables)

    def init_feeds(self,connection=url_typedb,clear_all=True):
        '''
        Clear ALL will destroy the entire database and should be discouraged.
        It will destroy all other feeds etc.

        :param connection:
        :param clear_all:
        :return:
        '''
        import_type = import_type_factory.get_all_imports()
        typedb_source = TypeDBSource(connection, import_type)
        typedb_sink = TypeDBSink(connection,clear_all, import_type)


        marking_def_statement = MarkingDefinition(
            definition_type="statement",
            definition=StatementMarking("Phishing Database...")
        )

        ip_a = ExternalReference(source_name="Phishing Database ACTIVE",
                                 external_id="phishing-IPs-ACTIVE.txt",
                                 url="https://github.com/mitchellkrogza/Phishing.Database/blob/master/phishing-IPs-ACTIVE.txt")

        ip_ia = ExternalReference(source_name="Phishing Database ACTIVE",
                                 external_id="phishing-IPs-ACTIVE.txt",
                                 url="https://github.com/mitchellkrogza/Phishing.Database/blob/master/phishing-IPs-INACTIVE.txt")

        ip_in = ExternalReference(source_name="Phishing Database ACTIVE",
                                 external_id="phishing-IPs-ACTIVE.txt",
                                 url="https://github.com/mitchellkrogza/Phishing.Database/blob/master/phishing-IPs-INVALID.txt")

        # create the Feeds object
        '''
        feeds = Feeds(name='phishing-db',
                      description="the phishing database",
                      paid=False,
                      free=True,
                      labels=["active","inactive","invalid","ip"],
                      lang="en",
                      external_references=[ip_a,ip_ia,ip_in],
                      object_marking_refs = [marking_def_statement],
                      contained=[])

        results = typedb_sink.add([ip_a,ip_ia,ip_in,marking_def_statement,feeds])
        '''

        feeds = Feeds(name='phishing-db',
                      description="the phishing database",
                      paid=False,
                      free=True,
                      labels=["active","inactive","invalid","ip"],
                      lang="en",
                      #object_marking_refs = [marking_def_statement],
                      contained=[])

        results = typedb_sink.add([feeds])

        for result in results:
            # TODO: check this runs good
            logger.info(f"Status = {result.status} ID = {result.id} Error = {result.error}")

        return True


from optparse import OptionParser
if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-i", "--init", dest="init",action="store_true",
                      help="initialize database")

    parser.add_option("-r", "--run", dest="run",action="store_true",
                      help="initialize database")

    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="don't print status messages to stdout")

    (options, args) = parser.parse_args()

    if options.init:
        import_type = import_type_factory.get_all_imports()

        typedb_sink = TypeDBSink(url_typedb, True, import_type)

        loader = Loader(typedb_sink)

        logger.info("Init database")
        loader = Loader(typedb_sink)
        loader.init_feeds()
    if options.run:

        import_type = import_type_factory.get_all_imports()

        typedb_sink = TypeDBSink(url_typedb, True, import_type)

        loader = Loader(typedb_sink)

        loader.add_IP_phish()

