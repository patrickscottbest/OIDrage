# OIDrage
A lightweight SNMPv2c server for testing purposes.  Sends very limited responses of test data.  Designed to scale.

# Updates
20221208 - Initiate Project - Complimentery to https://github.com/patrickscottbest/hammerOID

# About OIDrage
A lightweight SNMPv2c setup to mimic thousands of datapoints for a real cacti installation.  

This software is designed to be raw, quick, and not feature-bloated for mimicing real world load testing and KPI evaluations.  The usual PySNMP libraries are not used.  This software is stand-alone and requires Python 3.3+ for IP address module support.

The input file is a valid snmpwalk output (numerical).  
Either provide your own mimic.txt using "snmpwalk -v2c -c public -On 127.0.0.1 .1 > mimic.txt", or just use the default provided.

# Config Inputs and Styling
Allows various configuration inputs
- specify mimic-file, or use included.
- response delay (in ms, default 15, recommended 100 for WAN emulation) 
- Interface - (defualt lo at 127.0.0.1 || integer16_increment from .1)
- UDP Port (514 || integer16_increment_from_514)

# Implementation
Create a mimic tree using an snmpwalk or use the included default (a linux system)
Python script can run on a singular host, default binding to 127.0.0.1 on standard port 514.
Values returned are static.
A python script designed to make use of raw UDP port message and answer .

# Future
OID tree characteristics 
  - depth of OID tree (in layers)
  - length of OID response (in bytes, b(response:answer)) 
Prep script for system config, multiple loopback interfaces and systemctl control parameters if needed.


# Notes 

OID Types
https://www.rfc-editor.org/rfc/rfc1902.html#section-7.1.1

Curses upon you, ITU-T X.690 ANS.1 (Abstract Syntax Notation 1) BER (Basic Encoding Rules)
https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf


## Encoding Notes

SNMP message encoding requires the use of maths in 3 circumstances

- OID node numbers
- SNMP "length denotations" peppered throughout responses are encoded
- OID values of type Integer32 are signed, and also encoded.

Understanding the OID node values encoding took a lot of investigation.  
OIDs are variable-length and there is a flag and mathematical formula used to calculate them as the OID OBJECT_NAME is examined.

Not only are the OID nodes themselves encoded with variable length, but the placeholders/positions in the bytes response for "bytes to follow" (eg, bytes length) also need to be accomodated with the same encoding scheme.

I've also discovered that OID values that are Integer32 have some kind of unique calculation performed. 0xFF is -1 in decimal.  0x0400 is 1024decimal.  0x01 is 1 decimal.


## OID implementation


Great breakdowns and images of actual byte sequences.  https://www.ranecommercial.com/legacy/note161.html


https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier?redirectedfrom=MSDN

More on Variable Length Quantity (ASN.1 encoding) https://stackoverflow.com/questions/5929050/how-does-asn-1-encode-an-object-identifier



Found in https://github.com/wireshark/wireshark/blob/master/epan/oids.c#L1115


		if (subid <= 0x0000007F) {
			bytelen += 1;
		} else if (subid <= 0x00003FFF ) {
			bytelen += 2;
		} else if (subid <= 0x001FFFFF ) {
			bytelen += 3;
		} else if (subid <= 0x0FFFFFFF ) {
			bytelen += 4;
		} else {
			bytelen += 5;
		}
	}
		switch(len) {
			default: *bytes_p=NULL; return 0;
			case 5: *(b++) = ((subid & 0xF0000000) >> 28) | 0x80;
			/* FALL THROUGH */
			case 4: *(b++) = ((subid & 0x0FE00000) >> 21) | 0x80;
			/* FALL THROUGH */
			case 3: *(b++) = ((subid & 0x001FC000) >> 14) | 0x80;
			/* FALL THROUGH */
			case 2: *(b++) = ((subid & 0x00003F80) >> 7)  | 0x80;
			/* FALL THROUGH */
			case 1: *(b++) =   subid & 0x0000007F ; break;

