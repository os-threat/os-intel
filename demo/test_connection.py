# try this on Debian version 10 +
'''
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster

'''
from typedb.client import *
import time
# give it a wait until Typedb is booting...
time.sleep(4)

client = TypeDB.core_client('typedb:1729')

print(client)