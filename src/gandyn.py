#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import sys
import argparse
import configparser
import traceback
import xmlrpc.client
import logging
import ipretriever
import ipretriever.adapter


class GandiDomainUpdater(object):
    """ Updates a gandi DNS record value."""
    def __init__(self, url, api_key, domain_name, record):
        """Constructor

        Keyword arguments:
        api_key -- The gandi XML-RPC api key.
                   You have to activate it on gandi website.
        domain_name -- The domain whose record will be updated
        record -- Filters that match the record to update
        """
        self.api_key = api_key
        self.domain_name = domain_name
        self.record = record
        self.__api = xmlrpc.client.ServerProxy(url)
        self.__zone_id = None

    def listDomains(self):
        """Retrieve the domains list."""
        logging.debug("key %s", self.api_key)
        domains = self.__api.domain.list(
            self.api_key
            )
        logging.debug("domains %d %s", len(domains), str(domains))

        infos = self.__api.domain.list(
            self.api_key,
            self.domain_name
            )
        logging.debug("infos %s", infos)

    def __get_active_zone_id(self):
        """Retrieve the domain active zone id."""
        if self.__zone_id is None:
            self.__zone_id = self.__api.domain.info(
              self.api_key,
              self.domain_name
              )['zone_id']
        return self.__zone_id

    def get_record_value(self):
        """Retrieve current value for the record to update."""
        zone_id = self.__get_active_zone_id()
        logging.debug('Active zone ID : %s', zone_id)

        rec = self.__api.domain.zone.record.list(self.api_key, zone_id, 0,
                                                 self.record)
        logging.debug("Retrieved record %s" % rec)

        return rec[0]['value']

    def update_record_value(self, new_value, ttl=300):
        """Updates record value.

        Update is done on a new zone version. If an error occurs,
        that new zone is deleted. Else, it is activated.
        This is an attempt of rollback mechanism.
        """
        new_zone_version = None
        zone_id = self.__get_active_zone_id()
        try:
            # Create new zone version
            new_zone_version = self.__api.domain.zone.version.new(
              self.api_key,
              zone_id
              )
            logging.debug('DNS working on a new zone (version %s)',
                          new_zone_version)
            record_list = self.__api.domain.zone.record.list(
              self.api_key,
              zone_id,
              new_zone_version,
              self.record
              )
            # Update each record that matches the filter
            for a_record in record_list:
                # Get record id
                a_record_id = a_record['id']
                a_record_name = a_record['name']
                a_record_type = a_record['type']

                # Update record value
                new_record = self.record.copy()
                new_record.update({'name': a_record_name,
                                   'type': a_record_type,
                                   'value': new_value,
                                   'ttl': ttl})
                updated_record = self.__api.domain.zone.record.update(
                   self.api_key,
                   zone_id,
                   new_zone_version,
                   {'id': a_record_id},
                   new_record
                   )
        except xmlrpc.client.Fault as e:
            # delete updated zone
            if new_zone_version is not None:
                self.__api.domain.zone.version.delete(
                    self.api_key,
                    zone_id,
                    new_zone_version
                    )
            raise
        else:
            # activate updated zone
            self.__api.domain.zone.version.set(
              self.api_key,
              zone_id,
              new_zone_version
              )


def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-c", "--config", help="config file")
        parser.add_argument("--debug", help="debug mode", action='store_true')
        parser.add_argument("--console", help="logging in console",
                            action='store_true')
        parser.add_argument("-f", "--force", help="force gandy dns update",
                            action='store_true')

        group = parser.add_mutually_exclusive_group(required=False)
        group.add_argument('--autodiscovery', dest='autoDiscovery',
                           help='Auto discovery of the external ip address',
                           action='store_true')
        group.add_argument('--ip', dest='currentIP',
                           help='Indicate current external ip address',
                           action='store')

        args = parser.parse_args()

        # Load configuration
        config = configparser.ConfigParser()
        sample_config = """
[GANDI]
GANDI_API_URL=https://rpc.gandi.net/xmlrpc/
API_KEY=
[DOMAIN]
DOMAIN_NAME = mydomain.com
TTL=300
RECORD = {'type':'A', 'name':'@'}
[LOG]
LOG_LEVEL = INFO
LOG_FILE = gandyn.log
"""
        config = configparser.ConfigParser(allow_no_value=True)
        config.read_string(sample_config)

        config.read(args.config)

        # Configure logger
        numeric_level = getattr(logging, config['LOG']['LOG_LEVEL'].upper(),
                                None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s'
                             % config['LOG']['LOG_LEVEL'])
        FORMAT = '%(asctime)s %(levelname)-8s %(message)s'
        DFORMAT = '%Y-%m-%d %H:%M:%S'
        handlers = [logging.FileHandler(config['LOG']['LOG_FILE'])]
        if args.console:
            handlers.append(logging.StreamHandler())
        if args.debug:
            numeric_level = logging.DEBUG
        logging.basicConfig(format=FORMAT, datefmt=DFORMAT,
                            level=numeric_level, handlers=handlers)

        if args.currentIP is None and not args.autoDiscovery:
            args.autoDiscovery = True

        if args.debug:
            for s in config.sections():
                logging.debug("SECTION %s" % s)
                for k in config.options(s):
                    logging.debug("  %s:%s" % (k, config[s][k]))
        logging.debug("Configuration loaded")
        logging.debug("")
    except:
        traceback.print_exc()
        exit(1)

    try:
        if args.autoDiscovery:
            # Get current ip address
            # public_ip_retriever = ipretriever.adapter.IPEcho()
            public_ip_retriever = ipretriever.adapter.IfConfig()
            logging.debug('Public_ip_retriever OK')
            current_ip_address = public_ip_retriever.get_public_ip()
            logging.debug('Current public IP address : %s', current_ip_address)

        if args.currentIP:
            current_ip_address = args.currentIP

        # You must authenticate yourself by passing
        # the API key as the first method's argument
        gandi_updater = GandiDomainUpdater(config['GANDI']['GANDI_API_URL'],
                                           config['GANDI']['API_KEY'],
                                           config['DOMAIN']['DOMAIN_NAME'],
                                           eval(config['DOMAIN']['RECORD']))
        logging.debug('Gandi_updater OK')

        if not args.force:
            # get DNS record ip address
            previous_ip_address = gandi_updater.get_record_value()
            logging.debug('Current DNS record IP address : %s',
                          previous_ip_address)

        if args.force or (current_ip_address != previous_ip_address):
            # Update record value
            logging.info('Updating DNS')
            gandi_updater.update_record_value(current_ip_address,
                                              eval(config['DOMAIN']['TTL']))
            logging.info('DNS updated')
        else:
            logging.debug('Public IP address unchanged. Nothing to do.')

    except xmlrpc.client.Fault as e:
        logging.error('An error occured using Gandi API : %s ', e)
    except ipretriever.Fault as e:
        logging.error('An error occured retrieving public IP address : %s', e)


if __name__ == '__main__':
    main()
    sys.exit(0)
