import requests
from stixorm.module.typedb import TypeDBSink, TypeDBSource, get_embedded_match
from typedb.client import *
from stixorm.module.orm.import_objects import raw_stix2_to_typeql
from stixorm.module.orm.delete_object import delete_stix_object
from stixorm.module.orm.export_object import convert_ans_to_stix
from stixorm.module.authorise import authorised_mappings, import_type_factory
from stixorm.module.parsing.parse_objects import parse
from stixorm.module.generate_docs import configure_overview_table_docs, object_tables
from stixorm.module.initialise import sort_layers, load_typeql_data
from stixorm.module.definitions.stix21 import ObservedData, IPv4Address
from stixorm.module.definitions.os_threat import Feed, ThreatSubObject
from stixorm.module.orm.import_utilities import val_tql

def load_threat_report(name='poisonivy.json')->dict:
    print(f'Loading... {name}')
    r= requests.get(f'https://raw.githubusercontent.com/os-threat/Stix-ORM/brett-attack-paolo/data/threat_reports/{name}')

    if r.status_code == 200:
        print('Done')
        return r.json()
    else:
        raise Exception(f'Unable to download {r.status_code}')

connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}

import_type = import_type_factory.get_all_imports()

# Notcie: install the stix-orm and requests as pip packages
if __name__ == '__main__':
    dict_report1 = load_threat_report(name='poisonivy.json')
    dict_report2 = load_threat_report(name='apt1.json')

    typedb_sink = TypeDBSink(connection, True, import_type)

    res1 = typedb_sink.add(dict_report1)
    res2 = typedb_sink.add(dict_report2)
