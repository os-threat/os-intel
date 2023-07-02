# try this on Debian version 10 +
'''
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster

'''
from typedb.client import *

client = TypeDB.core_client('localhost:1729')