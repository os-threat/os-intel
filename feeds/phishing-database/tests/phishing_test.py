import unittest
import requests
import ipaddress
import validators
from stix2 import Bundle, Identity, Indicator, IPv4Address,IPv6Address, Relationship, DomainName, URL
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class DownloadTestCase(unittest.TestCase):
    ROOT_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master'
    IP_PHISH_ACTIVE = 'phishing-IPs-ACTIVE.txt'

    def setUp(self) -> None:
        self.author = Identity(
            name="Phishing Database",
            identity_class="organization",
        )
    def test_IP_phish(self):
        for status in ['ACTIVE','INACTIVE','INVALID']:
            logger.info(f'IP {status}')
            r = requests.get(f"{self.ROOT_URL}/phishing-IPs-{status}.txt")

            if r.status_code == 200:
                total = 0
                for line in r.content.decode().split('\n'):
                    ipstr = line.strip()

                    if len(ipstr)>0:
                        try:
                            if validators.ip_address.ipv4(ipstr):
                                observable = IPv4Address(value=ipstr)
                                indicator = Indicator(
                                    name=observable.value,
                                    description="Phishing IP",
                                    created_by_ref=f"{self.author.id}",
                                    pattern_type="stix",
                                    pattern=f"[ipv4:value = '{observable.value}']",
                                    labels="phishing",
                                )
                            elif validators.ip_address.ipv6(ipstr):
                                observable = IPv6Address(value=ipstr)
                                indicator = Indicator(
                                    name=observable.value,
                                    description="Phishing IP",
                                    created_by_ref=f"{self.author.id}",
                                    pattern_type="stix",
                                    pattern=f"[ipv6:value = '{observable.value}']",
                                    labels="phishing",
                                )
                            total+=1
                        except Exception as e:
                            logger.error(f"Invalid IP address {ipstr}")
                self.assertGreater(total,0)
            else:
                raise Exception('Feed URL is down')

    def test_domain_phish(self):
        for status in ['ACTIVE','INACTIVE','INVALID']:
            logger.info(f'IP {status}')
            r = requests.get(f"{self.ROOT_URL}/phishing-domains-{status}.txt")

            if r.status_code == 200:
                total = 0
                for line in r.content.decode().split('\n'):
                    domain = line.strip()
                    if len(domain)>0 and validators.domain(domain):
                        total+=1
                        observable = DomainName(value=domain)

                self.assertGreater(total,0)
            else:
                raise Exception('Feed URL is down')

    def test_links_phish(self):
        for status in ['ACTIVE','INACTIVE','INVALID']:
            logger.info(f'IP {status}')
            r = requests.get(f"{self.ROOT_URL}/phishing-links-{status}.txt")

            if r.status_code == 200:
                total = 0
                for line in r.content.decode().split('\n'):
                    url = line.strip()
                    if len(url)>0 and validators.url(url):
                        total+=1
                        observable = URL(value=url)
                self.assertGreater(total,0)
            else:
                raise Exception('Feed URL is down')

if __name__ == '__main__':
    unittest.main()
