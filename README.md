# OIDrage
A lightweight SNMPv2c server for testing purposes.  Sends mimic responses of test data based on any snmpwalk output.  Designed to scale.

![OIDrage Logo](logo/png/logo-no-background.png?raw=true "OIDrage Logo")

# About OIDrage
A lightweight SNMPv2c setup to mimic an entire MIB tree of datapoints.  Can be easily spawned over and over to replicate thousands of live machines.  Use as a standalone python script, or deploy as a container from dockerhub using oidrage:latest.

This software is designed to be raw, quick, and not feature-bloated.  It can mimic existing snmp mibs for load testing and metrics-gathering-platforms evaluation.  
For example, a real cacti installation or a cli snmp transaction against multiple auto-discoverable targets. 

No library dependencies.  It is stand-alone and requires Python 3.3+ for IP address module support.  The usual PySNMP libraries is not required, in fact, there is no requirements.txt. 

The input file is a valid snmpwalk output (numerical).  
Either provide your own mimic.txt using "snmpwalk -v2c -c public -On 127.0.0.1 .1 > mimic.txt", or just use the default provided.

By default, any community string will work.  Alternatively, one can be set and will be required.

<a href="https://www.buymeacoffee.com/pbest"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=pbest&button_colour=40DCA5&font_colour=ffffff&font_family=Cookie&outline_colour=000000&coffee_colour=FFDD00" /></a>

# How to Run

A number of ways to use and scale.

1.  Python

Download the source code and run manually from the command line, any OS: 
```
python3 ./OIDrage.py --help
```


2. DockerHub

Call the oidrage:latest image to use the latest docker image at [DockerHub](https://hub.docker.com/repository/docker/patrickscottbest/oidrage):

```
docker run --name OIDrageTEST --env COMMUNITY=private -p 5005:161 oidrage:latest  
```


# Options

By default, no options are required, optional configurations are as below.

OIDrage can be configured via the command line (priority), or by environment variables.

## Command Line

For complete features, run "python3 OIDrage.py -h"

```
usage: OIDrage.py [-h] [-f INPUTFILE] [-i IPADDRESS] [-p PORT] [-d DELAY]
                  [-c COMMUNITY] [-D DEBUG]

OIDrage SNMPd Mimic Server by Patrick Scott Best

optional arguments:
  -h, --help            show this help message and exit
  -f INPUTFILE, --inputfile INPUTFILE
                        Input file. [mimic.txt]
  -i IPADDRESS, --ipaddress IPADDRESS
                        IP Address. [127.0.0.1]
  -p PORT, --port PORT  UDP port number to bind to. [161]
  -d DELAY, --delay DELAY
                        Response delay, in milliseconds. [0]
  -c COMMUNITY, --community COMMUNITY
                        Require a specific community string from client. [*]
  -D DEBUG, --debug DEBUG
                        Debug
```

## Environment Variables

Makes this suitable for containerisation. 

- INPUTFILE
- IPADDRESS
- PORT
- DELAY
- COMMUNITY
- DEBUG  (presence, set to anything)


# Implementation

Create a mimic tree using an snmpwalk or use the included default (a linux system)
Python script can run on a singular host, default binding to 127.0.0.1 on standard port 161.
Values returned are static.
A python script designed to make use of raw UDP port message and answer .

# Updates

- 20221208 - Initiate Project - Complimentery to https://github.com/patrickscottbest/hammerOID
- 20221218 - Ready for walks and for individual gets, new logo.
- 20221221 - Ready for bulk.  Tested against Cacti.
- 20221224 - Opaque float added.
- 20221229 - Ready for first release.


# Future

- "Wiggle" of common parameters (cpu / mem / interface).  This will be accomplished with threading and a shared dictionary class.
- Custom hostnames per instance.
- Timeticks will move upwards.


# Contributing

I would love you to contribute to OIDrage, pull requests are welcome!  

Besides feature coding, I could also use a hand with our SNMPwalk collection.

We are always happy to see examples of SNMPwalk outputs from various devices:

- routers
- switches
- IoT devices
- Various computer types
- Toasters ???


# Notes 

## Web Resources

OID Types found in [RFC 1902](https://www.rfc-editor.org/rfc/rfc1902.html#section-7.1.1)

Curses upon you, ITU-T X.690 ANS.1 (Abstract Syntax Notation 1) BER (Basic Encoding Rules) at [ITU](https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf)

Python Argparse Tutorial by [Sam Starkman's Medium](https://sestarkman.medium.com/?source=---two_column_layout_sidebar----------------------------------) and [Toward Data Science](
https://towardsdatascience.com/a-simple-guide-to-command-line-arguments-with-argparse-6824c30ab1c3)
Argparse syntax [python docs](https://docs.python.org/3/library/argparse.html)
Argparse tutorial [python docs](https://docs.python.org/3/howto/argparse.html)

Getbulk explanations at [net-snmp](https://net-snmp.sourceforge.io/wiki/index.php/GETBULK#:~:text=non%2Drepeaters,max%2Drepetitions) and [web-nms](https://www.webnms.com/snmp/help/snmpapi/snmpv3/snmp_operations/snmp_getbulk.html)

Setting Environment variables in vscode with a [great stackoverflow response](https://stackoverflow.com/questions/64944122/use-environment-variables-in-vscode)
VS Code python environments overview [visual studio](https://code.visualstudio.com/docs/python/environments#_python-environments)
VS Code suppress certain PEP8 warnings [stackoverflow response](https://stackoverflow.com/questions/40831593/visual-studio-code-suppress-pep8-warnings)

Best description of OPAQUE Float values [stackoverflow response](https://stackoverflow.com/questions/35276556/snmpsharpnet-opaque-float)


## Encoding Notes

SNMP message encoding requires the use of maths in 3 circumstances

- OID node numbers, when > 127 or 0x7F
- SNMP "length denotations" peppered throughout responses are encoded
- OID values of type Integer32 are signed, and also encoded.

Understanding the OID node values encoding took a lot of investigation.  
OIDs are variable-length and there is a flag and mathematical formula used to calculate them as the OID OBJECT_NAME is examined.

Not only are the OID nodes themselves encoded with variable length, but the placeholders/positions in the bytes response for "bytes to follow" (eg, bytes length) also need to be accomodated with the same encoding scheme.

I've also discovered that OID values that are Integer32 have some kind of unique calculation performed. 0xFF is -1 in decimal.  0x0400 is 1024decimal.  0x01 is 1 decimal.

Opaque type OID values are typically IEEE 754 32-bit floats.  It was really hard to find a standalone example of conversion.


## OID implementation

Great breakdowns and images of actual byte sequences.  https://www.ranecommercial.com/legacy/note161.html

https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier?redirectedfrom=MSDN

More on Variable Length Quantity (ASN.1 encoding) https://stackoverflow.com/questions/5929050/how-does-asn-1-encode-an-object-identifier

There's a myriad of ways to calculate, but my first real clue was found in the wireshark codebase
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

