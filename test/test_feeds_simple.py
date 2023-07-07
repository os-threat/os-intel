import json
import os

import dateutil.parser
from dateutil.parser import *
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

import logging

#from stixorm.module.typedb_lib.import_type_factory import AttackDomains, AttackVersions

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
#logger.addHandler(logging.StreamHandler())


# define the database data and import details
connection = {
    "uri": "localhost",
    "port": "1729",
    "database": "stix",
    "user": None,
    "password": None
}

import_type = import_type_factory.get_all_imports()

marking =["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
          "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
          "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]

get_ids = 'match $ids isa stix-id;'


test_id = "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
marking_id = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
file_id = 'file--364fe3e5-b1f4-5ba3-b951-ee5983b3538d'


def test_get_ids(connection, import_type):
    typedb_sink = TypeDBSink(connection, False, import_type)
    my_id_list = typedb_sink.get_stix_ids()
    print(f'myidlist {my_id_list}')

def test_get(stixid):
    typedb_source = TypeDBSource(connection, import_type)
    stix_obj = typedb_source.get(stixid, None)
    return stix_obj

def test_auth():
    # import_type = import_type_factory.create_import(stix_21=True,
    #                                                 os_hunt=True,
    #                                                 os_intel=True,
    #                                                 cacao=True,
    #                                                 attack_domains=[AttackDomains.ENTERPRISE_ATTACK, AttackDomains.ICS_ATTACK, AttackDomains.MOBILE_ATTACK],
    #                                                 attack_versions=[AttackVersions.V12_1])

    auth = authorised_mappings(import_type)
    print("===========================================")
    print(auth)

# ObservedData, IPv4Address, Feed, ThreatSubObject
def test_feeds():
    osthreat = "data/os-threat/feed-example/example.json"
    datetime1 = dateutil.parser.isoparse("2020-10-19T01:01:01.000Z")
    datetime2 = dateutil.parser.isoparse("2020-10-20T01:01:01.000Z")
    datetime3 = dateutil.parser.isoparse("2020-10-21T01:01:01.000Z")
    typedb_source = TypeDBSource(connection, import_type)
    typedb_sink = TypeDBSink(connection, True, import_type)

    json_data =[
      [
        "127.0.0.1",
        "196.0.0.1",
        "226.98.34.2",
        "135.32.43.54"
      ],
      [
        "127.0.0.1",
        "196.0.0.1",
        "226.98.34.20",
        "135.32.43.54"
      ],
      [
        "127.0.0.1",
        "196.0.0.1",
        "226.98.34.20",
        "135.32.43.54",
        "127.3.2.15"
      ]
    ]

    # first lets create the feed
    feed_id = create_feed(json_data[0], typedb_sink, datetime1)
    print(f'feed id -> {feed_id}')
    update_feed(feed_id, json_data[1], datetime2, typedb_source, typedb_sink)


def update_feed(feed_id, local_list, loc_datetime, typedb_source, typedb_sink):
    # get the feed
    sco_map = {}
    sco_loaded_list = []
    feed_obj = typedb_source.get(feed_id, None)
    # get the observed data objects
    loc_contents = feed_obj["contents"]
    for loc_content in loc_contents:
        observed_id = loc_content["object_ref"] # get the observed data id
        observed_obj = typedb_source.get(observed_id, None)
        sco_list = observed_obj["object_refs"]
        # we make the assumption there is only one sco for every observed-data object
        for sco in sco_list:
            sco_obj = typedb_source.get(sco, None)
            sco_map[sco_obj["value"]] = observed_obj

    # build the list of scos that are laoded already
    sco_loaded_list = list(sco_map.keys())
    set_sco_loaded = set(sco_loaded_list)
    set_new_sco = set(local_list)
    update_date_list = list(set_sco_loaded & set_new_sco)
    revoke_list = list(set_sco_loaded - set_new_sco)
    insert_list = list(set_new_sco - set_sco_loaded)
    # plus new ips
    print(f'\n==== revoke =====\n{revoke_list}')
    revoke_observed(feed_id, revoke_list, sco_map)
    print(f"\n==== update =====\n{update_date_list}")
    update_observed_and_feed_dates(feed_id, update_date_list, sco_map, loc_datetime)
    print(f'\n==== insert =====\n{insert_list}')
    insert_observed(feed_id, insert_list, loc_datetime, typedb_sink)
    print("===============================================")


def insert_observed(feed_id, insert_list, loc_datetime, typedb_sink):
    ips = []
    observed = []
    obs_ids = []
    insert_tql_list = []
    for ipaddr in insert_list:
        ip = IPv4Address(value=ipaddr)
        ips.append(ip)
        obs = ObservedData(
            first_observed=loc_datetime,
            last_observed=loc_datetime,
            number_observed=1,
            object_refs =[ip.id]
        )
        observed.append(obs)
        obs_ids.append(obs.id)

    add_list = ips + observed
    typedb_sink.add(add_list)

    for obs_id in obs_ids:
        insert_tql = 'match $obs isa observed-data, has stix-id "' + obs_id + '";'
        insert_tql += '$feed isa feed, has stix-id "' + feed_id + '";' # get the feed
        insert_tql += 'insert $sub isa threat-sub-object, has created ' + val_tql(loc_datetime) + ','
        insert_tql += 'has modified ' + val_tql(loc_datetime) + ';'
        insert_tql += '$objref (container:$sub,content:$obs) isa obj-ref;'
        insert_tql += '$content (content:$sub, feed-owner:$feed) isa feed-content;'
        insert_tql_list.append(insert_tql)

    insert_typeql_data(insert_tql_list, connection)


def revoke_observed(feed_id, revoke_list, sco_map):
    insert_tql_list = []
    update_tql_list = []
    for rev in revoke_list:
        observed_obj = sco_map[rev]
        if not getattr(observed_obj, "revoked", False):
            # revoke the observed data object, but the revoke property is there and is false, so update to make it true
            revoke_tql = 'match $x isa observed-data, has stix-id "' + observed_obj['id'] + '";'
            revoke_tql += 'insert $x has revoked true;'
            insert_tql_list.append(revoke_tql)

    #update_typeql_data(update_tql_list, connection)
    insert_typeql_data(insert_tql_list, connection)


def update_observed_and_feed_dates(feed_id, update_date_list, sco_map, loc_datetime):
    update_tql_list = []
    obs_id_list = []
    feed_update_list = []
    # update the observed data objects
    for up in update_date_list:
        observed_obj = sco_map[up]
        obs_id_list.append(observed_obj["id"])
        # update the observed data object, modified, and last observed and feed modified
        update_obs_tql = 'match $obs isa observed-data, has stix-id "' + observed_obj['id'] + '",'
        update_obs_tql += 'has last-observed $last_obs, has modified $mod, has number-observed $num_obs;'
        update_obs_tql += 'delete $obs has $last_obs; $obs has $mod; $obs has $num_obs;'
        update_obs_tql += 'insert $obs has last-observed ' + val_tql(loc_datetime) + ';'
        update_obs_tql += '$obs has modified ' + val_tql(loc_datetime) + ';' # this is the observed data object
        update_obs_tql += '$obs has number-observed ' + str(observed_obj['number_observed'] + 1) + ';'
        update_tql_list.append(update_obs_tql)

    # update the threat sub object
    for obs_id in obs_id_list:
        update_threat_tql = 'match $feed isa feed, has stix-id "' + feed_id + '";'
        update_threat_tql += '$obs isa observed-data, has stix-id "' + obs_id + '";'
        update_threat_tql += '$threat isa threat-sub-object, has modified $mod;'
        update_threat_tql += '$objref (container:$threat,content:$obs) isa obj-ref;'
        update_threat_tql += '$content (content:$threat, feed-owner:$feed) isa feed-content;'
        update_threat_tql += 'delete $threat has $mod;'
        update_threat_tql += 'insert $threat has modified ' + val_tql(loc_datetime) + ';'
        feed_update_list.append(update_threat_tql)

    # update the feed object modified date
    update_feed_tql = 'match $feed isa feed, has stix-id "' + feed_id + '";'
    update_feed_tql += '$feed has modified $mod;'
    update_feed_tql += 'delete $feed has $mod;'
    update_feed_tql += 'insert $feed has modified ' + val_tql(loc_datetime) + ';' # this is the feed object
    feed_update_list.append(update_feed_tql)
    # update the typeql
    update_typeql_data(update_tql_list, connection)
    update_typeql_data(feed_update_list, connection)


def create_feed(local_list, typedb_sink, loc_datetime):
    ips = []
    observed = []
    threatsubobj = []
    for ipaddr in local_list:
        ip = IPv4Address(value=ipaddr)
        ips.append(ip)
        obs = ObservedData(
            first_observed=loc_datetime,
            last_observed=loc_datetime,
            number_observed=1,
            object_refs =[ip.id]
        )
        observed.append(obs)
        sub = ThreatSubObject(
            object_ref=obs.id,
            created=loc_datetime,
            modified=loc_datetime
        )
        threatsubobj.append(sub)

    feed = Feed(
        name="OS Threat Feed",
        description="OS Threat Test Feed",
        created=loc_datetime,
        contents=[
            threatsubobj[0],
            threatsubobj[1],
            threatsubobj[2],
            threatsubobj[3]
        ]
    )
    add_list = ips + observed + [feed]
    typedb_sink.add(add_list)
    return feed.id


def update_typeql_data(data_list, stix_connection: Dict[str, str]):
    url = stix_connection["uri"] + ":" + stix_connection["port"]
    with TypeDB.core_client(url) as client:
        # Update the data in the database
        with client.session(stix_connection["database"], SessionType.DATA) as session:
            with session.transaction(TransactionType.WRITE) as update_transaction:
                logger.debug(f'==================== updating feed concepts =======================')
                for data in data_list:
                    logger.debug(f'\n\n{data}\n\n')
                    insert_iterator = update_transaction.query().update(data)

                    logger.debug(f'insert_iterator response ->\n{insert_iterator}')
                    for result in insert_iterator:
                        logger.info(f'typedb response ->\n{result}')

                update_transaction.commit()


def insert_typeql_data(data_list, stix_connection: Dict[str, str]):
    url = stix_connection["uri"] + ":" + stix_connection["port"]
    with TypeDB.core_client(url) as client:
        # Update the data in the database
        with client.session(stix_connection["database"], SessionType.DATA) as session:
            with session.transaction(TransactionType.WRITE) as insert_transaction:
                logger.debug(f'=========== inserting feed concepts ===========================')
                for data in data_list:
                    logger.debug(f'\n\n{data}\n\n')
                    insert_iterator = insert_transaction.query().insert(data)

                    logger.debug(f'insert_iterator response ->\n{insert_iterator}')
                    for result in insert_iterator:
                        logger.info(f'typedb response ->\n{result}')

                insert_transaction.commit()

# load the feeds
if __name__ == '__main__':
    test_feeds()
