import unittest
import requests
import ipaddress

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class DownloadTestCase(unittest.TestCase):
    ROOT_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master'
    IP_PHISH_ACTIVE = 'phishing-IPs-ACTIVE.txt'
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
                            ip = ipaddress.ip_address(ipstr)

                            if ip.version == 4: pass
                            elif ip.version == 6: pass
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
                    if len(domain)>0:
                        total+=1

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
                    if len(url)>0:
                        total+=1
                self.assertGreater(total,0)
            else:
                raise Exception('Feed URL is down')

if __name__ == '__main__':
    unittest.main()
