# OIDrage.py 
# Patrick Scott Best, 2022
# https://github.com/patrickscottbest/OIDrage

# References: 
# UDP Comm https://wiki.python.org/moin/UdpCommunication#CA-60759983b77d9e5650a253e88b9ac4b5e607d69c_3
# SNMP RFCs https://datatracker.ietf.org/doc/html/rfc1906#section-8

import socket
import sys
import ipaddress # makes this program only 3.3 compliant
from pprint import pprint

file1 = open('mimic.txt', 'r')
Lines = file1.readlines()


def OID_to_hex(oid_string):
    # takes an entire oid string and encodes an SNMP compliant hex chain

    if not oid_string.startswith(".1.3.6"):
        print("does not oid start with 136")
        raise ValueError("Does not start as how we planned")

    oid_hex = bytearray()
    oid_hex.extend(b'\x2b')
    #oid_hex.extend(int(15).to_bytes(1, 'big'))
    oid_array = oid_string.split('.')
    oid_array.pop(0)  # remove first blank
    oid_array.pop(0)  # next two are forgone as 0x2B
    oid_array.pop(0)  # next two are forgone as 0x2B

    #pprint(oid_array)

    for level in oid_array:
        #print (f"level {level}")
        if (int(level)) < 128:
            oid_hex.extend(int(level).to_bytes(1, 'big'))
        elif (int(level)) < 16535:
            #print(f"BIG BOY HERE: {level}")

            # 1. we need to work with two separate parts of the bytes.
            # 1a. blank out the right byte , shift to left, mark the MSB as a 1
            left = (( int(level) & 65280 ) << 1 ) | 32768
            #print (f'left is {left}')
            # 1b. set the left-most bit of the right-most byte to zero
            right = (int(level) & 255 ) & 127
            #print(f'right is {right}')
            # 2. smash them together
            together = left + right
            
            oid_hex.extend(int(together).to_bytes(2, 'big'))

        else:
            
            print (f"TOO BIG: {int(level)}")
            raise ValueError("too big")

    #print(f'oid_hex is {oid_hex.hex()}')
    return oid_hex


def get_tree_dict(Line):
    # returns a dict 

    oid_string = Line.split("=", 1)[0].strip()
    oid_hex = OID_to_hex(oid_string)
    #print (f"oid_string: {oid_string}")
    oid_type = Line.split("=", 1)[1].split(":", 1)[0].strip()

    #print (f"oid_type: {oid_type} hex: {oid_type.encode('utf-8').hex()} vartype: {type(oid_type)}")

    if oid_type == "STRING":
        oid_value = Line.split("=", 1)[1].split(":", 1)[1].strip()
    elif oid_type == "Hex-STRING":
        oid_value = Line.split("=")[1].split(":")[1].strip()
    elif oid_type == "IpAddress":
        oid_value = int(ipaddress.ip_address(Line.split("=")[1].split(":")[1].strip()))
    elif oid_type == "INTEGER":
        oid_value = int(Line.split("=", 1)[1].split(":")[1].strip())
    elif oid_type == "Counter32":
        oid_value = int(Line.split("=", 1)[1].split(":")[1].strip())
    elif oid_type == "Counter64":
        oid_value = int(Line.split("=", 1)[1].split(":")[1].strip())
    elif oid_type =="Gauge32":
        oid_value = int(Line.split("=", 1)[1].split(":")[1].strip())
    elif oid_type =="Gauge64":
        oid_value = int(Line.split("=", 1)[1].split(":")[1].strip())
    elif oid_type == "OID":
        oid_value = Line.split("=", 1)[1].split(":")[1].strip()
    elif oid_type == "Timeticks":
        oid_value = int(Line.split("=", 1)[1].split(":", 1)[1].strip().split("(")[1].split(")", 1)[0])
    elif oid_type == "\"\"":
        oid_type = "_none_"
        oid_value = ""
    else:
        print(f"Unkown OID type: {oid_type}.  Line: {Line}")
        raise Exception

    #print (f"oid_value: {oid_value}")
    return {"oid_string": oid_string, "oid_hex": oid_hex, "oid_type": oid_type, "oid_value": oid_value}


tree = []
count = 0
problems = 0
# Strips the newline character
for line in Lines:
    count += 1
    #print("Importing Line{}: {}".format(count, line.strip()))
    try:
        tree.append(get_tree_dict(line))
    except:
        print("Problem importing this one.")
        problems += 1

print (f'problems: {problems} total reviewed: {count} tree size: {len(tree)}')
#pprint(tree)



UDP_IP = "127.0.0.1"
UDP_IP = "10.0.1.178"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

def print_hex_nicely(data):

    #print(type(data))
    count = 1
    for i in data:
        if count % 8 == 0:
            print(f'{i:02X} ')
        else:
            print(f'{i:02X} ', end='')

        count += 1
    print('')

def request_valid(data):
    # Examines that a request is valid and returns BOOL
    # <FALLTHROUGH>
    
    if ((data[0] != 30)  # snmp request type
    | (data[2] != 2) # version demarc
    | (data[3] != 1)):  # version
        return False
    else:
        return True


def extract_request_details(data):
    # Returns what is needed to reformulate the overhead for a valid response.
    # assumes a walk
    
    try:
        # Community string
        if data[5] == 4:  # demarc for community  
            comm_length = data[6]
            community = ""
            for i in range(comm_length):
                community += chr(data[7+i])
            print(f'community string: {community}')

        else: 
            raise Exception

        # request ID
        cursor = 5 + comm_length + 5

        request_id = bytearray(4)
        for i in range(0,4):
            request_id[i] = data[cursor + i]
        print(f'request_id: {int.from_bytes(request_id, "big")} ({request_id})')
        cursor += 4

        # Advance the cursor to the OID length definition, accounting for 11 bytes of unnecessary error codes and index.
        cursor += 12

        # oid_requested
        oid_len = data[cursor]
        print(f'oid_len is {oid_len}')
        cursor += 1

        oid_requested = bytearray(oid_len)
        for i in range(0, oid_len):
            oid_requested[i] = data[cursor + i]
        cursor += oid_len
        print(f'oid_requested:') 
        print_hex_nicely(oid_requested)

        return request_id, oid_requested

    except Exception as e:
        print(f'Problem: {e}')
    
    # request type (right now just walk supported)
    # requested OID 

    return community

def end_of_mib():
    pass

while True:
    data, addr = sock.recvfrom(1460) # buffer size is 1024 bytes
    
    # diagnostics
    print("received message: string: %s" % data)
    print_hex_nicely(data)


    # Validate the request 
    try: 
        if not request_valid:
            print("Request is Not Valid.")
        else:
            print("Request is Valid.")

        # Extract the peices we need 
        request_id, oid_requested = extract_request_details(data)

        
        # search the tree elements for a dict for a direct match.  If found, simply pass the next element of the tree.
        tree_cursor = 0
        for t in range(0,len(tree)):
            if tree[t]['oid_hex'] == oid_requested:
                print(f"Direct OID match at branch position {t}. ")
                if t == (len(tree) - 1):
                    # there's nothing left.  Send back EndOfMib
                    print("sending EndOfMib")
                    end_of_mib()
                else:
                    print(f"sending Valid Response based on {t + 1} {tree[t+1]}")

                tree_cursor = t
        
        if tree_cursor == 0:
            
            # we couldn't find a direct match... time to get fancy and find the next best thing.
            # the match should be closest to the top of the tree as possible.

            len_oid_requested = len(oid_requested)
            high_score = 0
            high_score_cursor = 0
        
            game_on = True
            
            print('Could not find direct match.  Searching for closest branch.')
            # compare the requested OID bytes with branch's bytes to the maximum depth of the first part of the matched bytes.
            while game_on:

                # figure out how many bytes deep this comparison will be.
                len_oid_branch = len(tree[tree_cursor]['oid_hex'])
                if len_oid_branch < len_oid_requested:
                    compare_depth = len_oid_branch
                else:
                    compare_depth = len_oid_requested

                # roll through the bytes sequentially and see how many matched bytes we have 
                
                matches = 0
                for current_depth in range(0, compare_depth):
                    
                    if tree[tree_cursor]['oid_hex'][current_depth] == oid_requested[current_depth]:
                        matches += 1
                    else:
                        break

                if matches > high_score:
                    #print(f'matches breaks highscore of {high_score} with cursor position of {tree_cursor} and new high of {matches}')
                    high_score = matches
                    high_score_cursor = tree_cursor
                elif matches < high_score:
                    # we clearly came across a better match before here.  
                    game_on = False
                
                if tree_cursor == (len(tree) - 1):
                    game_on = False
                else:
                    tree_cursor += 1

            print(f'ROUND ONE')
            print(f'Best match depth: {high_score} at tree cursor position {high_score_cursor}')
            print(f'Record before the match is {tree[high_score_cursor - 1]}')
            print(f'Match record is {tree[high_score_cursor]}')
            #print(f'Last record is {tree[len(tree)-1]}')

            ## ROUND 2 , unfinished business.
            # check the very next record again.  If it's matches are lower, then forget it, we've got a winner.

            # if not, then we need to start evaluating the next "branch" for when the value is the next highest.


            # If the next tree entry would be beyond the end of the dict, formulate a "endOfMibView"
            if high_score_cursor == (len(tree) -1) :
                print("This is the EndOfMibView")
                end_of_mib()

            elif high_score == len(oid_requested):
                # The length of the requested oid lends to no further examination.
                print(f'The return record will be tree element {high_score_cursor}.')

            else:
                # the tree_cursor is one behind the possible target branch.  
                # Let's see if the next branch is even in the ballpark with the requested OID prefix.
                
                print("Examining the non-matching byte branch")

                game_on = True
                while game_on: 
                    
                    ballpark = True
                    for b in range(0,matches-1):
                        if oid_requested[b] != tree[high_score_cursor + 1]['oid_hex'][b]:
                            ballpark = False
                            # fallthrough

                    if not ballpark: 
                        print(f'The return record will be tree element {high_score_cursor}.')
                    else:
                        
                        print(f'Proceeding with scoring against element {high_score_cursor + 1}')
                        
                        if oid_requested[matches] > tree[high_score_cursor + 1]['oid_hex'][matches]:
                            print(f'the requested OID byte is greater than this, we have a new champ')
                            high_score_cursor +=1 
                        else: 
                            print(f'the requested OID byte is less than this.  We have the final next record.')
                            game_on = False
                # end game on

                print(f'the next record to hand back is tree element {high_score_cursor+1}.  {tree[high_score_cursor+1]}')
        

    except Exception as e:
        print(f'Exception: {e}')




### Datagram: Example get-next-request
#        <> Always 30
#           <> 0x34 (48)bytes to follow in this SNMP request 
#              <---> demarc 02 01
#                    <> version 
#                       <> demarc 04
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

# print("UDP target IP: %s" % UDP_IP)
# print("UDP target port: %s" % UDP_PORT)
# print("message: %s" % MESSAGE)

# sock = socket.socket(socket.AF_INET, # Internet
#                      socket.SOCK_DGRAM) # UDP
# sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
