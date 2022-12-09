# OIDrage.py 
# Patrick Scott Best, 2022
# https://github.com/patrickscottbest/OIDrage

# References: 
# UDP Comm https://wiki.python.org/moin/UdpCommunication#CA-60759983b77d9e5650a253e88b9ac4b5e607d69c_3
# SNMP RFCs https://datatracker.ietf.org/doc/html/rfc1906#section-8


# RECEIVING 

import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    print("received message: string: %s" % data)
    #":".join("{:02x}".format(ord(c)) for c in data)
    print(type(data))
    enriched = data.hex().upper()

    here = 1
    for digit in enriched: 
        if here % 3 == 0:
            print(digit + " ")
        else:
            print(digit.strip())
        here += 1

        


### Example get-next-request
#        <> unknown, always 30
# #        <> 0x34 (48)bytes to follow in this SNMP request 
#              <---> demarc 02 01
#                    <> version 
#                       <> demarc 04
#                          <> 0x06 (6)bytes to follow containing community string
#                             <---------------> "public"
#                                               <---> demarc
#                                                     <- data get-next-request(1) demarc
#
# 0000   30 34 02 01 01 04 06 70 75 62 6c 69 63 a1 27 02   04.....public.'.

#        -> demarc end, always 02 04
#           <---------> request ID
#                       <----> demarc
#                             <> error-code
#                                <---> dmarc
#                                      <> error index
#                                         <---> dmarc
#                                               <---> variable binding , 1 item
#                                                     <> demarc
# 0010   04 27 59 8f 30 02 01 00 02 01 00 30 19 30 17 06   .'Y.0......0.0..


#        <> bytes to follow including trailing dmarc, 8bit, 0x13 (19) bytes until end. 
#           <------------------------------------------- object name (OID 1.3.6.1.6.3.16.1.5.2.1.6.5.95.97.108.108.95.1.1 )   
#           <> meaning 1.3. though i dont know how.
#              <---------> meaning .6.1.6.3. (@4bit)
#                          <> meaning .16. (@8bit)
#                             <-------------------------> meaning .1.5.2.1.6.5.96.97.108. (@8bit)
#
# 0020   13 2b 06 01 06 03 10 01 05 02 01 06 05 5f 61 6c   .+..........._al

#        ----------> object name (FINAL)
#        <---------> meaning .108.95.1.1
#                    <---> demarc
#
# 0030   6c 5f 01 01 05 00                                 l_....

# Frame 33937: 96 bytes on wire (768 bits), 96 bytes captured (768 bits) on interface lo, id 0
# Ethernet II, Src: 00:00:00_00:00:00 (00:00:00:00:00:00), Dst: 00:00:00_00:00:00 (00:00:00:00:00:00)
# Internet Protocol Version 4, Src: 127.0.0.1, Dst: 127.0.0.1
# User Datagram Protocol, Src Port: 37723, Dst Port: 161
#     Source Port: 37723
#     Destination Port: 161
#     Length: 62
#     Checksum: 0xfe51 [unverified]
#     [Checksum Status: Unverified]
#     [Stream index: 1]
#     [Timestamps]
#     UDP payload (54 bytes)
# Simple Network Management Protocol
#     version: v2c (1)
#     community: public
#     data: get-next-request (1)
#         get-next-request
#             request-id: 660180784
#             error-status: noError (0)
#             error-index: 0
#             variable-bindings: 1 item
#                 1.3.6.1.6.3.16.1.5.2.1.6.5.95.97.108.108.95.1.1: Value (Null)
#                     Object Name: 1.3.6.1.6.3.16.1.5.2.1.6.5.95.97.108.108.95.1.1 (iso.3.6.1.6.3.16.1.5.2.1.6.5.95.97.108.108.95.1.1)
#                     Value (Null)
#     [Response In: 33938]


# Example get-response

# 0000   30 35 02 01 01 04 06 70 75 62 6c 69 63 a2 28 02   05.....public.(.
# 0010   04 27 59 8f 30 02 01 00 02 01 00 30 1a 30 18 06   .'Y.0......0.0..
# 0020   13 2b 06 01 06 03 10 01 05 02 01 06 05 5f 61 6c   .+..........._al
# 0030   6c 5f 01 02 02 01 01                              l_.....

# Frame 33938: 97 bytes on wire (776 bits), 97 bytes captured (776 bits) on interface lo, id 0
# Ethernet II, Src: 00:00:00_00:00:00 (00:00:00:00:00:00), Dst: 00:00:00_00:00:00 (00:00:00:00:00:00)
# Internet Protocol Version 4, Src: 127.0.0.1, Dst: 127.0.0.1
# User Datagram Protocol, Src Port: 161, Dst Port: 37723
#     Source Port: 161
#     Destination Port: 37723
#     Length: 63
#     Checksum: 0xfe52 [unverified]
#     [Checksum Status: Unverified]
#     [Stream index: 1]
#     [Timestamps]
#     UDP payload (55 bytes)
# Simple Network Management Protocol
#     version: v2c (1)
#     community: public
#     data: get-response (2)
#         get-response
#             request-id: 660180784
#             error-status: noError (0)
#             error-index: 0
#             variable-bindings: 1 item
#                 1.3.6.1.6.3.16.1.5.2.1.6.5.95.97.108.108.95.1.2: 1
#                     Object Name: 1.3.6.1.6.3.16.1.5.2.1.6.5.95.97.108.108.95.1.2 (iso.3.6.1.6.3.16.1.5.2.1.6.5.95.97.108.108.95.1.2)
#                     Value (Integer32): 1
#     [Response To: 33937]
#     [Time: 0.000134535 seconds]








# SENDING 

# import socket

# UDP_IP = "127.0.0.1"
# UDP_PORT = 5005
# MESSAGE = b"Hello, World!"

# print("UDP target IP: %s" % UDP_IP)
# print("UDP target port: %s" % UDP_PORT)
# print("message: %s" % MESSAGE)

# sock = socket.socket(socket.AF_INET, # Internet
#                      socket.SOCK_DGRAM) # UDP
# sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
