
### Datagram: Example get-next-request
#        <> Always 30
#           <> 0x34 (48)bytes to follow in this SNMP request 
#              <---> demarc 02 01
#                    <> version 
#                       <> length of comm string 04
#                          <> 0x06 (6)bytes to follow containing community string
#                             <---------------> "public"
#                                               <> demarc a1
#                                                  <> 0x27 (39)bytes remaining until end
#                                                     <> demarc 02, data get-next-request(1)
# 0000   30 34 02 01 01 04 06 70 75 62 6c 69 63 a1 27 02   04.....public.'.

#        <> demarc end, always 02 then 04 (len of request ID)
#           <---------> request ID
#                       <----> demarc 02 01
#                             <> error-code 00
#                                <---> dmarc 02 01
#                                      <> error index
#                                         <> dmarc 30
#                                            <> 0x19 (25)bytes until end
#                                               <> dmarc variable binding , 1 item
#                                                  <> 0x17 (23)bytes until end
#                                                     <> demarc 06
# 0010   04 27 59 8f 30 02 01 00 02 01 00 30 19 30 17 06   .'Y.0......0.0..


#        <> 0x13 (19)bytes until end of OBJECT NAME
#           <------------------------------------------- object name (OID 1.3.6.1.6.3.16.1.5.2.1.6.5.95.97.108.108.95.1.1 )   
#           <> meaning 1.3. though i dont know how.
#              <---------------------------------------> meaning .6.1.6.3.16.1.5.2.1.6.5.96.97.108.
#
# 0020   13 2b 06 01 06 03 10 01 05 02 01 06 05 5f 61 6c   .+..........._al


#        ----------> object name (FINAL)
#        <---------> meaning .108.95.1.1
#                    <> demarc
#                       <> zero bytes to follow as OBJECT VALUE (null)
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


# Example get-response INTEGER

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



# Example get-response OCTECT STRING

# 0000   30 81 84 02 01 01 04 06 70 75 62 6c 69 63 a2 77   0.......public.w
# 0010   02 04 20 61 54 91 02 01 00 02 01 00 30 69 30 67   .. aT.......0i0g
# 0020   06 08 2b 06 01 02 01 01 01 00 04 5b 4c 69 6e 75   ..+........[Linu
# 0030   78 20 6b 61 6c 69 20 36 2e 30 2e 30 2d 6b 61 6c   x kali 6.0.0-kal
# 0040   69 33 2d 61 6d 64 36 34 20 23 31 20 53 4d 50 20   i3-amd64 #1 SMP 
# 0050   50 52 45 45 4d 50 54 5f 44 59 4e 41 4d 49 43 20   PREEMPT_DYNAMIC 
# 0060   44 65 62 69 61 6e 20 36 2e 30 2e 37 2d 31 6b 61   Debian 6.0.7-1ka
# 0070   6c 69 31 20 28 32 30 32 32 2d 31 31 2d 30 37 29   li1 (2022-11-07)
# 0080   20 78 38 36 5f 36 34                               x86_64

# Frame 2: 177 bytes on wire (1416 bits), 177 bytes captured (1416 bits) on interface lo, id 0
# Ethernet II, Src: 00:00:00_00:00:00 (00:00:00:00:00:00), Dst: 00:00:00_00:00:00 (00:00:00:00:00:00)
# Internet Protocol Version 4, Src: localhost.localdomain (127.0.0.1), Dst: localhost.localdomain (127.0.0.1)
# User Datagram Protocol, Src Port: 161, Dst Port: 51800
# Simple Network Management Protocol
#     version: v2c (1)
#     community: public
#     data: get-response (2)
#         get-response
#             request-id: 543249553
#             error-status: noError (0)
#             error-index: 0
#             variable-bindings: 1 item
#                 1.3.6.1.2.1.1.1.0: "Linux kali 6.0.0-kali3-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.0.7-1kali1 (2022-11-07) x86_64"
#                     Object Name: 1.3.6.1.2.1.1.1.0 (iso.3.6.1.2.1.1.1.0)
#                     Value (OctetString): "Linux kali 6.0.0-kali3-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.0.7-1kali1 (2022-11-07) x86_64"
#                         Variable-binding-string: Linux kali 6.0.0-kali3-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.0.7-1kali1 (2022-11-07) x86_64
#     [Response To: 1]
#     [Time: 0.000180582 seconds]








# SENDING 

# import socket

# UDP_IP = "127.0.0.1"
# UDP_PORT = 5005
# MESSAGE = b"Hello, World!"

# logging.debug("UDP target IP: %s" % UDP_IP)
# logging.debug("UDP target port: %s" % UDP_PORT)
# logging.debug("message: %s" % MESSAGE)

# sock = socket.socket(socket.AF_INET, # Internet
#                      socket.SOCK_DGRAM) # UDP
# sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
