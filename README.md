# OIDrage
A lightweight SNMP server for testing purposes.  Sends very limited responses of test data.  Designed to scale.

# Updates
20221208 - Initiate Project - Complimentery to https://github.com/patrickscottbest/hammerOID

# About OIDrage
I needed a setup to mimic 15,000 datapoints for a cacti installation.  The intention is to allow various configuration inputs such as: 

- delayed response (in ms, default 15, recommended 100 for WAN emulation) 
- OID tree characteristics 
- - depth of OID tree (in layers)
- - length of OID response (in bytes, b(response:answer)) 
- response types (GUAGE/COUNTER64/STRING)
- Loopback style (127.0.0.1 | integer16_increment_from_.1)
- Port style (514 | integer16_increment_from_514)


A python script designed to make use of raw UDP port message and answer.

# Implementation
Python script will be built to run on a singular host, binding to 127.0.0.1 on standard port 514.
A prep-script will accompany that will configure a system for multiple loopback interfaces.
Other 

