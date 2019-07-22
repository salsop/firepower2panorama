# Firewall to Palo Alto Networks Config Migration Scrit

## Thank you! 

Big Thankyou to DAXM for the fantastic work on FMCAPI.
https://github.com/daxm/fmcapi

## Requirements

The following items need to be installed for this script to work:
 * Python 3
 * requests
 * requests_cache

```bash
pip3 install requests
pip3 install requests_cache
```

## How to use this script

Change the variables in the script to match your environemnt, it is best to use a seperate login or one you will not use during the migration.

```python
CISCO_FMC_USERNAME = 'api-user'
CISCO_FMC_PASSWORD = 'password'
CISCO_FMC_HOSTNAME = 'hostname or IP'
```

To execute this script you can run with the Python 3 interpreter, or directly from the command line:

```bash
Python3 ./firepower2panorama.py
```

```bash
chmod +x ./firepower2panorama.py
./firepower2panorama.py
```

You can check any errors by checking the OUTPUT.LOG file:
```bash
grep output.log | grep CRITICAL
2019/07/20-23:03:00 - CRITICAL:firepower2panorama.py:260 - Unknown protocol for Service: SKIP
2019/07/20-23:03:00 - CRITICAL:firepower2panorama.py:249 - Confirm Port Value for Service:udp-any
2019/07/21-00:04:21 - CRITICAL:firepower2panorama.py:424 - Source Ports Found: tcp-57000
```

Once executed this script exports the following files:

* address1.xml
* address2.xml
* address3.xml
* address4.xml
* address-group.xml
* service.xml
* service-group.xml
* [policy-files].xml

You can then import these files in Panorama:

1. Login to Panorama.
2. Goto the Panorama tab from the top of the menu.
3. Select Import named Panorama configuration snapshot.
4. Select all of the files and upload them all.
5. Once uploaded, SSH to Panorama.
6. Enable configuration mode:
```
Panorama> configure
Panorama#
```
7. Then import the configurations into the candidate configuration by using the following commands:

### Importing Address Objects (Networks, Hosts, IP Ranges, Literals from Address Groups)
```
load config partial to-xpath /config/shared/address from address1.xml mode merge from-xpath /config/shared/address
load config partial to-xpath /config/shared/address from address2.xml mode merge from-xpath /config/shared/address
load config partial to-xpath /config/shared/address from address3.xml mode merge from-xpath /config/shared/address
load config partial to-xpath /config/shared/address from address4.xml mode merge from-xpath /config/shared/address
```

### Importing Address Groups
```
load config partial to-xpath /config/shared/address-group from-xpath /config/shared/address-group mode merge from address-groups.xml
```

### Service and Service Groups:
You may need to adjust some of these, dependent on the output from the OUTPUT.LOG file.
```
load config partial to-xpath /config/shared/service from-xpath /config/shared/service mode merge from service.xml
load config partial to-xpath /config/shared/service-group from-xpath /config/shared/service-group mode merge from service-group.xml
```

### Security Policies
Change POLICY.XML to the various polcies that were generated from the script.
```
load config partial to-xpath /config/devices from-xpath /config/devices mode merge from POLICY.XML
```


## Known Issues:

* Not all Port/Service types are correctly exported, some additional work on services and policies is required after the inital export. These are highlighted in the OUTPUT.LOG file.
* All ports are assumed to be destination ports, and Source ports are hightlighted in the OUTPUT.LOG file.
* ICMP missing from Services in Security Policy, these are not currently highlighted in the OUTPUT.LOG file.

