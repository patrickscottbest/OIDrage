# OIDrage
A lightweight SNMP server for testing purposes.  Sends very limited responses of test data.  Designed to scale.

# Updates
20221208 - Initiate Project - Complimentery to https://github.com/patrickscottbest/hammerOID

# About OIDrage
A quick setup to mimic thousands datapoints for a real cacti installation.  This software is designed to be raw, quick, and not feature bloated for mimicing real world load testing and KPI evaluations.  The regular PySNMP libraries are not required.  This software is stand-alone.


# Config Inputs and Styling
Allows various configuration inputs

- delayed response (in ms, default 15, recommended 100 for WAN emulation) 
- OID tree characteristics 
  - depth of OID tree (in layers)
  - length of OID response (in bytes, b(response:answer)) 
- response types (GUAGE/COUNTER64/STRING)
- Loopback style (127.0.0.1 | integer16_increment_from_.1)
- Port style (514 | integer16_increment_from_514)


# Implementation
Python script can run on a singular host, default binding to 127.0.0.1 on standard port 514.
Values returned are static.
A python script designed to make use of raw UDP port message and answer .

# Future
Prep script for system config, multiple loopback interfaces and systemctl control parameters if needed.


