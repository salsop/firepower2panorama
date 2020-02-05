#!/usr/bin/env python3
'''
===============================================================================================================================================================
#   Cisco Firepower to Palo Alto Networks Panorama Configuration Migration Script
===============================================================================================================================================================
'''
# CISCO FIREPOWER MANAGEMENT CENTER CONFIGURATION
CISCO_FMC_USERNAME = 'apiuser'
CISCO_FMC_PASSWORD = 'apipassword'
CISCO_FMC_HOSTNAME = 'cisco-fmc-hostname'

# from github.com/daxm/fmcapi
from fmcapi.fmc import *
from fmcapi.api_objects import *

import datetime
import sys
import os
import requests_cache
import logging

# Configure Requests Cache
requests_cache.install_cache(cache_name='cache_name', backend=None, expire_after=21600)

START_TIME = datetime.datetime.now()
print('Started: ' + str(START_TIME))
logging.info('Started.')
CREATED_OBJECTS = []

def export_hosts():
    global CREATED_OBJECTS

    logging.info('Started Create_Hosts Function.')
    logging.info('Getting Cisco FMC IP Host Objects')
    XML = ''
    XML += '<config>\n'
    XML += '  <shared>\n'
    XML += '    <address>\n'

    with FMC(host=CISCO_FMC_HOSTNAME, username=CISCO_FMC_USERNAME, password=CISCO_FMC_PASSWORD, autodeploy=False) as FMC_CONNECTION:
        CISCO_FMC_OBJECT = IPHost(fmc=FMC_CONNECTION)
        CISCO_FMC_HOSTS = CISCO_FMC_OBJECT.get()['items']
        TOTAL = len(CISCO_FMC_HOSTS)
        print('HOSTS:' + str(TOTAL))
        COUNTER = 0
        for CISCO_FMC_HOST in CISCO_FMC_HOSTS:
            if not(CISCO_FMC_HOST['name'] in CREATED_OBJECTS):
                COUNTER += 1
                logging.info('[' + str(COUNTER) + '/' + str(TOTAL) + '] ' + CISCO_FMC_HOST['name'] + ' : ' + CISCO_FMC_HOST['value'])
                XML += '      <entry name="' + CISCO_FMC_HOST['name'] + '">\n'
                XML += '        <ip-netmask>' + CISCO_FMC_HOST['value'] + '</ip-netmask>\n'
                XML += '        <description>Imported Host or Network Object</description>\n'
                XML += '      </entry>\n'

                CREATED_OBJECTS.append(CISCO_FMC_HOST['name'])


    XML += '    </address>\n'
    XML += '  </shared>\n'
    XML += '</config>\n'

    logging.info('Writing to address1.xml file.')
    XML_FILE = open('address1.xml', 'w')
    XML_FILE.write(XML)
    XML_FILE.close

def export_networks():
    logging.info('Started Create_Hosts Function.')
    logging.info('Getting Cisco FMC IP Network Objects')
    XML = ''
    XML += '<config>\n'
    XML += '  <shared>\n'
    XML += '    <address>\n'

    with FMC(host=CISCO_FMC_HOSTNAME, username=CISCO_FMC_USERNAME, password=CISCO_FMC_PASSWORD, autodeploy=False) as FMC_CONNECTION:
        CISCO_FMC_OBJECT = IPNetwork(fmc=FMC_CONNECTION)
        CISCO_FMC_NETWORKS = CISCO_FMC_OBJECT.get()['items']
        TOTAL = len(CISCO_FMC_NETWORKS)
        print('NETWORKS:' + str(TOTAL))
        COUNTER = 0
        for CISCO_FMC_NETWORK in CISCO_FMC_NETWORKS:
            COUNTER += 1
            logging.info('[' + str(COUNTER) + '/' + str(TOTAL) + '] ' + CISCO_FMC_NETWORK['name'] + ' : ' + CISCO_FMC_NETWORK['value'])

            XML += '      <entry name="' + CISCO_FMC_NETWORK['name'] + '">\n'
            XML += '        <ip-netmask>' + CISCO_FMC_NETWORK['value'] + '</ip-netmask>\n'
            XML += '        <description>Imported Host or Network Object</description>\n'
            XML += '      </entry>\n'

    XML += '    </address>\n'
    XML += '  </shared>\n'
    XML += '</config>\n'

    logging.info('Writing to address4.xml file.')
    XML_FILE = open('address4.xml', 'w')
    XML_FILE.write(XML)
    XML_FILE.close

def export_addressgroups():
    global CREATED_OBJECTS
    
    logging.info('Getting Cisco FMC Network Group Objects')
    
    XML_1 = ''
    XML_1 += '<config>\n'
    XML_1 += '  <shared>\n'
    XML_1 += '    <address>\n'
    XML_2 = ''
    XML_2 += '<config>\n'
    XML_2 += '  <shared>\n'
    XML_2 += '    <address-group>\n'
    
    with FMC(host=CISCO_FMC_HOSTNAME, username=CISCO_FMC_USERNAME, password=CISCO_FMC_PASSWORD, autodeploy=False) as FMC_CONNECTION:
        CISCO_FMC_OBJECT = NetworkGroup(fmc=FMC_CONNECTION)
        CISCO_FMC_NETWORKGROUPS = CISCO_FMC_OBJECT.get()['items']
        TOTAL = len(CISCO_FMC_NETWORKGROUPS)
        print('NETWORK GROUPS:' + str(TOTAL))
        COUNTER = 0
        for CISCO_FMC_NETWORKGROUP in CISCO_FMC_NETWORKGROUPS:
            COUNTER += 1
            MEMBERS = []

            logging.info('[' + str(COUNTER) + '/' + str(TOTAL) + '] ' + CISCO_FMC_NETWORKGROUP['name'] + ' : ' + str(MEMBERS))

            if CISCO_FMC_NETWORKGROUP['name'] == 'any':
                continue

            XML_2 += '      <entry name="' + CISCO_FMC_NETWORKGROUP['name'] + '">\n'
            XML_2 += '        <static>\n'

            try:
                for OBJECT in CISCO_FMC_NETWORKGROUP['objects']:
                    XML_2 += '          <member>' + OBJECT['name'] + '</member>\n'
            except:
                logging.error('NetworkGroup: ' + CISCO_FMC_NETWORKGROUP['name'] + ' has no objects.')

            try:
                for OBJECT in CISCO_FMC_NETWORKGROUP['literals']:
                    if not(OBJECT['value'] in CREATED_OBJECTS):
                        NAME = OBJECT['value']
                        NAME = NAME.replace('/','-cidr')

                        XML_1 += '      <entry name="' + NAME + '">\n'
                        XML_1 += '        <ip-netmask>' + OBJECT['value'] + '</ip-netmask>\n'
                        XML_1 += '        <description>Imported Host or Network Object</description>\n'
                        XML_1 += '      </entry>\n'

                        CREATED_OBJECTS.append(OBJECT['value'])

                    XML_2 += '          <member>' + NAME + '</member>\n'

            except:
                logging.error('NetworkGroup: ' + CISCO_FMC_NETWORKGROUP['name'] + ' has no literals.')

            XML_2 += '        </static>\n'
            XML_2 += '        <description>' + 'Test' + '</description>\n'
            XML_2 += '      </entry>\n'


    XML_1 += '    </address>\n'
    XML_1 += '  </shared>\n'
    XML_1 += '</config>\n'
    XML_2 += '    </address-group>\n'
    XML_2 += '  </shared>\n'
    XML_2 += '</config>\n'

    logging.info('Writing to address2.xml file.')
    XML_FILE = open('address2.xml', 'w')
    XML_FILE.write(XML_1)
    XML_FILE.close

    logging.info('Writing to address-groups.xml file.')
    XML_FILE = open('address-groups.xml', 'w')
    XML_FILE.write(XML_2)
    XML_FILE.close

def export_ranges():
    XML = ''
    XML += '<config>\n'
    XML += '  <shared>\n'
    XML += '    <address>\n'

    logging.info('Getting Cisco FMC IP Range Objects')
    with FMC(host=CISCO_FMC_HOSTNAME, username=CISCO_FMC_USERNAME, password=CISCO_FMC_PASSWORD, autodeploy=False) as FMC_CONNECTION:
        CISCO_FMC_OBJECT = IPRange(fmc=FMC_CONNECTION)
        CISCO_FMC_IPRANGES = CISCO_FMC_OBJECT.get()['items']
        TOTAL = len(CISCO_FMC_IPRANGES)
        print('RANGES:' + str(TOTAL))
        COUNTER = 0
        for CISCO_FMC_IPRANGE in CISCO_FMC_IPRANGES:
            COUNTER += 1
            logging.info('[' + str(COUNTER) + '/' + str(TOTAL) + '] ' + CISCO_FMC_IPRANGE['name'] + ' : ' + CISCO_FMC_IPRANGE['value'])

            XML += '      <entry name="' + CISCO_FMC_IPRANGE['name'] + '">\n'
            XML += '        <ip-range>' + CISCO_FMC_IPRANGE['value'] + '</ip-range>\n'
            XML += '        <description>Imported Host or Network Object</description>\n'
            XML += '      </entry>\n'

    XML += '    </address>\n'
    XML += '  </shared>\n'
    XML += '</config>\n'


    logging.info('Writing to address3.xml file.')
    XML_FILE = open('address3.xml', 'w')
    XML_FILE.write(XML)
    XML_FILE.close

def export_services():
    logging.info('Getting Cisco FMC Port Objects')

    XML = ''
    XML += '<config>\n'
    XML += '  <shared>\n'
    XML += '    <service>\n'

    with FMC(host=CISCO_FMC_HOSTNAME, username=CISCO_FMC_USERNAME, password=CISCO_FMC_PASSWORD, autodeploy=False) as FMC_CONNECTION:
        CISCO_FMC_OBJECT = Ports(fmc=FMC_CONNECTION)
        CISCO_FMC_PORTS = CISCO_FMC_OBJECT.get()['items']
        TOTAL = len(CISCO_FMC_PORTS)
        print('PORTS:' + str(TOTAL))
        COUNTER = 0
        for CISCO_FMC_PORT in CISCO_FMC_PORTS:
            COUNTER += 1

            logging.info('[' + str(COUNTER) + '/' + str(TOTAL) + '] ' + CISCO_FMC_PORT['name'])
            logging.info(CISCO_FMC_PORT)

            try:
                if CISCO_FMC_PORT['protocol'].lower() == 'tcp' or CISCO_FMC_PORT['protocol'].lower() == 'udp':

                    XML += '      <entry name="' + CISCO_FMC_PORT['name'] + '">\n'
                    XML += '        <protocol>\n'

                    if CISCO_FMC_PORT['protocol'].lower() == 'tcp':
                        XML += '          <tcp>\n'
                    if CISCO_FMC_PORT['protocol'].lower() == 'udp':
                        XML += '          <udp>\n'

                    try:
                        XML += '            <port>' + CISCO_FMC_PORT['port'] + '</port>\n'
                    except KeyError:
                        logging.critical('Confirm Port Value for Service:' + CISCO_FMC_PORT['name'])
                        XML += '            <port>0-65535</port>\n'

                    if CISCO_FMC_PORT['protocol'].lower() == 'tcp':
                        XML += '          </tcp>\n'
                    if CISCO_FMC_PORT['protocol'].lower() == 'udp':
                        XML += '          </udp>\n'

                    XML += '        </protocol>\n'
                    XML += '      </entry>\n'
                else:
                    logging.critical('Unknown protocol for Service: ' + CISCO_FMC_PORT['name'])

            except KeyError:
                logging.critical('Unknown protocol for Service: ' + CISCO_FMC_PORT['name'])

    XML += '    </service>\n'
    XML += '  </shared>\n'
    XML += '</config>\n'

    logging.info('Writing to service.xml file.')
    XML_FILE = open('service.xml', 'w')
    XML_FILE.write(XML)
    XML_FILE.close

    XML = ''
    XML += '<config>\n'
    XML += '  <shared>\n'
    XML += '    <service-group>\n'

    CISCO_FMC_OBJECT = PortObjectGroup(fmc=FMC_CONNECTION)
    CISCO_FMC_PORTGROUPS = CISCO_FMC_OBJECT.get()['items']
    TOTAL = len(CISCO_FMC_PORTGROUPS)
    print('PORTGROUPS:' + str(TOTAL))
    COUNTER = 0
    for CISCO_FMC_PORTGROUP in CISCO_FMC_PORTGROUPS:
        COUNTER += 1
        logging.info('[' + str(COUNTER) + '/' + str(TOTAL) + '] ' + CISCO_FMC_PORTGROUP['name'])

        XML += '      <entry name="' + CISCO_FMC_PORTGROUP['name'] + '">\n'
        XML += '        <members>\n'

        try:
            for OBJECT in CISCO_FMC_PORTGROUP['objects']:
                XML += '        <member>' + OBJECT['name'] + '</member>\n'
        except:
            logging.error('NetworkGroup: ' + CISCO_FMC_PORTGROUP['name'] + ' has no objects.')

        XML += '        </members>\n'
        XML += '      </entry>\n'

    XML += '    </service-group>\n'
    XML += '  </shared>\n'
    XML += '</config>\n'

    logging.info('Writing to service-group.xml file.')
    XML_FILE = open('service-group.xml', 'w')
    XML_FILE.write(XML)
    XML_FILE.close

def export_security_policy():
    logging.info('Export Cisco FMC Acess Policies')
    with FMC(host=CISCO_FMC_HOSTNAME, username=CISCO_FMC_USERNAME, password=CISCO_FMC_PASSWORD, autodeploy=False) as FMC_CONNECTION:
        CISCO_FMC_OBJECT = AccessControlPolicy(fmc=FMC_CONNECTION)
        CISCO_FMC_POLCIES = CISCO_FMC_OBJECT.get()['items']
        for CISCO_FMC_POLICY in CISCO_FMC_POLCIES:
            logging.info(CISCO_FMC_POLICY['id'] + ':' + CISCO_FMC_POLICY['name'])

        logging.info('Processing security policy from ' + CISCO_FMC_POLICY['name'])
        for CISCO_FMC_POLICY in CISCO_FMC_POLCIES:
            XML_FILE = open(CISCO_FMC_POLICY['name'] + '.xml', 'w+')

            XML = ''
            XML += '<config version="9.0.0" urldb="paloaltonetworks">\n'
            XML += '  <devices>\n'
            XML += '    <entry name="localhost.localdomain">\n'
            XML += '      <device-group>\n'
            XML += '        <entry name="' + CISCO_FMC_POLICY['name'] + '">\n'
            XML += '          <post-rulebase>\n'
            XML += '            <security>\n'
            XML += '              <rules>\n'

            CISCO_FMC_OBJECT = ACPRule(fmc=FMC_CONNECTION, acp_id=CISCO_FMC_POLICY['id'])
            CISCO_FMC_RULES = CISCO_FMC_OBJECT.get()['items']
            TOTAL = len(CISCO_FMC_RULES)
            COUNTER = 0

            CISCO_FMC_RULES_ORDERED = []

            CISCO_FMC_RULES_ORDERED = sorted(CISCO_FMC_RULES, key=lambda k: k['metadata']['ruleIndex'], reverse=False)

            for CISCO_FMC_RULE in CISCO_FMC_RULES_ORDERED:
                COUNTER += 1

                # RULE NAME with clean up of special chars
                RULE_NAME = CISCO_FMC_RULE['name']
                RULE_NAME = RULE_NAME.replace('/','_')
                RULE_NAME = RULE_NAME.replace('(','_')
                RULE_NAME = RULE_NAME.replace(')','_')
                logging.info('[' + str(COUNTER) + '/' + str(TOTAL) + '] FMC Rule Name: ' + CISCO_FMC_RULE['name'] + ' -> Panorama Rule Name: ' + RULE_NAME)

                XML += '          <entry name="' + RULE_NAME + '">\n'

                # RULE DISABLED
                RULE_DISABLED = not(CISCO_FMC_RULE['enabled'])

                # ACTION
                if CISCO_FMC_RULE['action'] == 'ALLOW':
                    XML += '            <action>allow</action>\n'
                elif CISCO_FMC_RULE['action'] == 'TRUST':
                    XML += '            <action>allow</action>\n'
                elif CISCO_FMC_RULE['action'] == 'BLOCK':
                    XML += '            <action>deny</action>\n'
                else:
                    logging.critical('Action is unknown: ' + CISCO_FMC_RULE['action'])

                # SOURCE ZONES
                XML += '            <from>\n'
                try:
                    for ZONE in CISCO_FMC_RULE['sourceZones']['objects']:
                        XML += '              <member>' + ZONE['name'] + '</member>\n'
                except KeyError:
                        XML += '              <member>any</member>\n'
                XML += '            </from>\n'

                # SOURCE NETWORKS
                XML += '            <source>\n'
                try:
                    for NETWORK in CISCO_FMC_RULE['sourceNetworks']['objects']:
                        XML += '              <member>' + NETWORK['name'] + '</member>\n'
                except KeyError:
                        XML += '              <member>any</member>\n'

                try:
                    for NETWORK in CISCO_FMC_RULE['sourceNetworks']['literals']:
                        XML += '              <member>' + NETWORK['name'] + '</member>\n'
                except KeyError:
                    pass
                XML += '            </source>\n'

                # DESTINATION ZONES        
                XML += '            <to>\n'
                try:
                    for ZONE in CISCO_FMC_RULE['destinationZones']['objects']:
                        XML += '              <member>' + ZONE['name'] + '</member>\n'
                except KeyError:
                        XML += '              <member>any</member>\n'
                XML += '            </to>\n'

                # DESTINATON NETWORKS
                XML += '            <destination>\n'
                try:
                    for NETWORK in CISCO_FMC_RULE['destinationNetworks']['objects']:
                        XML += '              <member>' + NETWORK['name'] + '</member>\n'
                except KeyError:
                        XML += '              <member>any</member>\n'

                try:
                    for NETWORK in CISCO_FMC_RULE['destinationNetworks']['literals']:
                        XML += '              <member>' + NETWORK['name'] + '</member>\n'
                except KeyError:
                    pass
                XML += '            </destination>\n'

                XML += '            <service>\n'
        
                # DESTINATION PORTS
                try:
                    for PORTS in CISCO_FMC_RULE['destinationPorts']['objects']:
                        XML += '              <member>' + PORTS['name'] + '</member>\n'
                except KeyError:
                    XML += '              <member>any</member>\n'

                # SOURCE PORTS
                try:
                    for PORTS in CISCO_FMC_RULE['sourcePorts']['objects']:
                        XML += '                <member>' + PORTS['name'] + '</member>\n'
                        logging.critical('Source Ports Found: ' + CISCO_FMC_POLICY['name'] + ' - ' + RULE_NAME + ' - ' + PORTS['name'])
                except KeyError:
                    logging.info('No Source Ports')                    

                XML += '              </service>\n'


                XML += '              <application>\n'
                XML += '                <member>any</member>\n'
                XML += '              </application>\n'
                XML += '              <category>\n'
                XML += '                <member>any</member>\n'
                XML += '              </category>\n'
                XML += '              <hip-profiles>\n'
                XML += '                <member>any</member>\n'
                XML += '              </hip-profiles>\n'
                XML += '              <source-user>\n'
                XML += '                <member>any</member>\n'
                XML += '              </source-user>\n'
                XML += '            </entry>\n'

            XML += '              </rules>\n'
            XML += '            </security>\n'
            XML += '          </post-rulebase>\n'
            XML += '        </entry>\n'
            XML += '      </device-group>\n'
            XML += '    </entry>\n'
            XML += '  </devices>\n'
            XML += '</config>\n'

            logging.info('\n' + XML)

            XML_FILE.write(XML)

def export_nats():
    logging.info('Export Cisco FMC NAT Policies')
    with FMC(host=CISCO_FMC_HOSTNAME, username=CISCO_FMC_USERNAME, password=CISCO_FMC_PASSWORD, autodeploy=False) as FMC_CONNECTION:
        CISCO_FMC_OBJECT = FTDNatPolicies(fmc=FMC_CONNECTION)
        CISCO_FMC_NAT_POLCIES = CISCO_FMC_OBJECT.get()['items']
        for CISCO_FMC_NAT_POLICY in CISCO_FMC_NAT_POLCIES:
            logging.info(CISCO_FMC_NAT_POLICY['id'] + ':' + CISCO_FMC_NAT_POLICY['name'])
            CISCO_FMC_NAT_OBJECT = ManualNatRules(fmc=FMC_CONNECTION)
            # CISCO_FMC_NAT_RULES = AutoNatRules(fmc=FMC_CONNECTION)
            CISCO_FMC_NAT_OBJECT.nat_policy(name=CISCO_FMC_NAT_POLICY['name'])
            CISCO_FMC_NAT_RULES = CISCO_FMC_NAT_OBJECT.get()['items']

            XML_FILE = open(CISCO_FMC_NAT_POLICY['name'] + '.xml', 'w+')

            XML = ''
            XML += '<config version="9.0.0" urldb="paloaltonetworks">\n'
            XML += '  <devices>\n'
            XML += '    <entry name="localhost.localdomain">\n'
            XML += '      <device-group>\n'
            XML += '        <entry name="' + CISCO_FMC_NAT_POLICY['name'] + '">\n'
            XML += '          <post-rulebase>\n'
            XML += '            <nat>\n'
            XML += '              <rules>\n'

            for CISCO_FMC_NAT_RULE in CISCO_FMC_NAT_RULES:

                XML += '                <entry name="NAT RULE INDEX ' + str(CISCO_FMC_NAT_RULE['metadata']['index']) + '">\n'

                # TO

                XML += '                  <to>\n'
                if CISCO_FMC_NAT_RULE.get('destinationInterface'):
                    XML += '                    <member>' + CISCO_FMC_NAT_RULE['destinationInterface']['name'] + '</member>\n'                
                else:
                    XML += '                    <member>any</member>\n'                
                XML += '                  </to>\n'
                
                # FROM

                XML += '                  <from>\n'
                if CISCO_FMC_NAT_RULE.get('sourceInterface'):
                    XML += '                    <member>' + CISCO_FMC_NAT_RULE['sourceInterface']['name'] + '</member>\n'                
                else:
                    XML += '                    <member>any</member>\n'                
                XML += '                  </from>\n'

                # SOURCE

                XML += '                  <source>\n'
                if CISCO_FMC_NAT_RULE.get('originalSource'):
                    XML += '                    <member>' + CISCO_FMC_NAT_RULE['originalSource']['name'] + '</member>\n'                
                else:
                    XML += '                    <member>any</member>\n'                
                XML += '                  </source>\n'

                # DESTINATION

                XML += '                  <destination>\n'
                if CISCO_FMC_NAT_RULE.get('originalDestination'):
                    XML += '                    <member>' + CISCO_FMC_NAT_RULE['originalDestination']['name'] + '</member>\n'                
                else:
                    XML += '                    <member>any</member>\n'                
                XML += '                  </destination>\n'

                # SERVICE

                if CISCO_FMC_NAT_RULE.get('originalSourcePort'):
                    XML += '                <service>' + CISCO_FMC_NAT_RULE['originalSourcePort']['name'] + '</service>\n'      
                else:
                    XML += '                <service>any</service>'          

                # DESCRIPTION

                if CISCO_FMC_NAT_RULE.get('description'):
                    XML += '                <description>' + CISCO_FMC_NAT_RULE['description'] + '</description>\n'                

                # TRANSLATED SOURCE

                if CISCO_FMC_NAT_RULE.get('translatedSource'):
                    XML += '                  <source-translation>\n'
                    XML += '                      <static-ip>\n'
                    XML += '                        <translated-address>' + CISCO_FMC_NAT_RULE['translatedSource']['name'] + '</translated-address>\n'     
                    XML += '                      </static-ip>\n'
                    XML += '                  </source-translation>\n'

                # TRANSLATED DESTINATION

                if CISCO_FMC_NAT_RULE.get('translatedDestination'):
                    XML += '                  <destination-translation>\n'
                    XML += '                      <static-ip>\n'
                    XML += '                        <translated-address>' + CISCO_FMC_NAT_RULE['translatedDestination']['name'] + '</translated-address>\n'     

                    if CISCO_FMC_NAT_RULE.get('translatedDestinationPort'):
                        XML += '                        <translated-port>' + CISCO_FMC_NAT_RULE['translatedDestinationPort']['name'] + '</translated-port>\n'

                    XML += '                      </static-ip>\n'
                    XML += '                  </destination-translation>\n'

                # ENABLED OR DISABLED

                if not(CISCO_FMC_NAT_RULE['enabled']):
                    XML += '                  <disabled>yes</disabled>\n'

                XML += '                </entry>\n'

            XML += '              </rules>\n'
            XML += '            </nat>\n'
            XML += '          </post-rulebase>\n'
            XML += '        </entry>\n'
            XML += '      </device-group>\n'
            XML += '    </entry>\n'
            XML += '  </devices>\n'
            XML += '</config>\n'

            logging.info('\n' + XML)

            XML_FILE.write(XML)

# ==================================================================================================================
#   MAIN CODE
# ==================================================================================================================
logging.info('Started:   ' + str(START_TIME))

# RUN ALL FUNCTIONS
export_hosts()
export_networks()
export_addressgroups()
export_ranges()
export_services()
export_security_policy()
export_nats()

# END CODE
END_TIME = datetime.datetime.now()
logging.info('Completed: ' + str(END_TIME))

print('Completed: ' + str(END_TIME))
print('Total Run Time:' + (str(END_TIME - START_TIME)))
