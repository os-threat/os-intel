import requests
import ipaddress
import validators
from stix2 import Bundle, Identity, Indicator, IPv4Address,IPv6Address, Relationship, DomainName, URL, ObservedData
from stix2 import utils
from stix2.exceptions import InvalidValueError
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

'''
Load all the STIX objects from that Phishing Database
Pleaes note that Observed-Data can only reference SRO and SCO but NOT Indicators.
Indicators needs to be referenced via additional SRO.
'''
class Loader():
    ROOT_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master'

    def __init__(self):
        self.author = Identity(
            name="Phishing Database",
            identity_class="organization",
        )
    def get_IP_phish(self,add_indicators=False)->Bundle:

        observables = []
        indicators = []

        total = 0

        for status in ['ACTIVE','INACTIVE','INVALID']:
            logger.info(f'IP {status}')
            r = requests.get(f"{self.ROOT_URL}/phishing-IPs-{status}.txt")

            if r.status_code == 200:

                for line in r.content.decode().split('\n'):
                    ipstr = line.strip()

                    if len(ipstr)>0:
                        try:
                            if validators.ip_address.ipv4(ipstr):
                                observable = IPv4Address(value=ipstr)
                                observables.append(observable)
                                indicator = Indicator(
                                    name=observable.value,
                                    description="Phishing IP",
                                    created_by_ref=f"{self.author.id}",
                                    pattern_type="stix",
                                    pattern=f"[ipv4:value = '{observable.value}']",
                                    labels=["phishing"],
                                )
                                indicators.append(indicator)
                            elif validators.ip_address.ipv6(ipstr):
                                observable = IPv6Address(value=ipstr)
                                indicator = Indicator(
                                    name=observable.value,
                                    description="Phishing IP",
                                    created_by_ref=f"{self.author.id}",
                                    pattern_type="stix",
                                    pattern=f"[ipv6:value = '{observable.value}']",
                                    labels=["phishing",status],
                                )
                            total+=1
                        except Exception as e:
                            logger.error(f"Invalid IP address {ipstr}")

            else:
                raise Exception('Feed URL is down')

        assert total > 0
        feedObservation = ObservedData(
            first_observed=utils.get_timestamp(),
            last_observed=utils.get_timestamp(),
            number_observed=total,
            created_by_ref=self.author,
            object_refs=observables
        )

        if add_indicators:
            rels = []
            for indicator in indicators:
                rel = Relationship(indicator, 'based-on', feedObservation)
                rels.append(rel)
                return Bundle(self.author, feedObservation, observables, rels, indicators)
        else:
            return Bundle(self.author, feedObservation, observables)

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

import pathlib


if __name__ == '__main__':

    # create a bundle to save the observation data
    folder = pathlib.Path(__file__).resolve().parent
    folder = folder/"data"/"bundles"
    folder.mkdir(parents=True, exist_ok=True)

    loader = Loader()

    # IP address
    bundle = loader.get_IP_phish()

    file_path = folder / "phishing-ip-observables.json"

    with open(file_path, 'w') as file:
        file.write(bundle.serialize())

    bundle = loader.get_IP_phish(add_indicators=True)

    file_path = folder / "phishing-ip-indicators.json"

    with open(file_path, 'w') as file:
        file.write(bundle.serialize())

    # DOMAIN
    bundle = loader.get_domain_phish()

    file_path = folder / "phishing-domain-observables.json"

    with open(file_path, 'w') as file:
        file.write(bundle.serialize())

    bundle = loader.get_domain_phish(add_indicators=True)

    file_path = folder / "phishing-domain-indicators.json"

    with open(file_path, 'w') as file:
        file.write(bundle.serialize())

    # URL

    bundle = loader.get_links_phish()

    file_path = folder / "phishing-url-observables.json"

    with open(file_path, 'w') as file:
        file.write(bundle.serialize())

    bundle = loader.get_links_phish(add_indicators=True)

    file_path = folder / "phishing-url-indicators.json"

    with open(file_path, 'w') as file:
        file.write(bundle.serialize())