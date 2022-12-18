# OIDrage.py 
# Patrick Scott Best, 2022
# https://github.com/patrickscottbest/OIDrage

# References: 
# UDP Comm https://wiki.python.org/moin/UdpCommunication#CA-60759983b77d9e5650a253e88b9ac4b5e607d69c_3
# SNMP RFCs https://datatracker.ietf.org/doc/html/rfc1906#section-8

import socket
import asn1.asn1 as asn1

encoder = asn1.Encoder()

import ipaddress # makes this program only 3.3 compliant

DEBUG = False

import logging
if not DEBUG: 
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
else:
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")


logging.info("Opening mimic file")
file1 = open('mimic.txt', 'r')
Lines = file1.readlines()


UDP_IP = "127.0.0.1"   # this will be the default.
UDP_IP = "10.0.1.124"  # test wired
UDP_IP = "10.0.1.178"  # test wireless
UDP_PORT = 5005


def print_hex_nicely(data):

    count = 1
    nice_hex = ""
    for i in data:
        if count % 16 == 0:
            nice_hex += f'{i:02X}'
            logging.debug(nice_hex)
            nice_hex = ""
        elif count % 8 == 0:
            nice_hex += f'{i:02X}  '
        else:
            nice_hex += f'{i:02X} '

        count += 1
    logging.debug(nice_hex)


def encode_variable_length(length):  # type: (int) -> bytes
    if length < 128:
        return length.to_bytes(1, 'big', signed=False)
    else:
        result = bytearray()
        values = []
        while length:
            values.append(length & 0xff)
            length >>= 8
        values.reverse()
        head = bytes([0x80 | len(values)])
        result.extend(head)
        for val in values:
            result.extend(bytes([val]))
        return result

def encode_variable_length_quantity(v:int) -> list:
    # Used for OIDs
    # Break it up in groups of 7 bits starting from the lowest significant bit
    # For all the other groups of 7 bits than lowest one, set the MSB to 1
    m = 0x00
    output = []
    while v >= 0x80:
        output.insert(0, (v & 0x7f) | m)
        v = v >> 7
        m = 0x80
    output.insert(0, v | m)
    return output


def encode_variable_length_quantity_allMSB1(v:int) -> list:
    # Sadly, a different encoding than the OIDs themselves use.
    # Used for length-byte representations
    # Break it up in groups of 7 bits starting from the lowest significant bit
    # If more than one output byte: for all groups set the MSB to 1
    m = 0x00
    output = []
    while v >= 0x80:
        output.insert(0, (v & 0x7f) | m)
        v = v >> 7
        m = 0x80
    output.insert(0, v | m)
    if len(output) > 1:
        for b in range(0,len(output)):
            output[b] = output[b] | 0x80
    return output


def OID_to_hex(oid_string):
    # takes an entire oid string and encodes an SNMP compliant hex chain

    if not oid_string.startswith(".1.3.6"):
        # this might be ok, I have witnessed ".0.0" be a value presented by an OID node.
        #raise ValueError("Does not start as how we planned")
        logging.warning(f"OID does not start with .1.3.6 - oid: {oid_string}")
        
    oid_hex = bytearray()
    oid_hex.extend(b'\x2b')
    #oid_hex.extend(int(15).to_bytes(1, 'big'))
    oid_array = oid_string.split('.')
    oid_array.pop(0)  # remove first blank
    oid_array.pop(0)  # next two are forgone as 0x2B
    oid_array.pop(0)  # next two are forgone as 0x2B


    for node in oid_array:
        #logging.debug (f"node {node}")
        if (int(node)) < 128:
            oid_hex.extend(int(node).to_bytes(1, 'big'))
        else:
            oid_hex.extend(encode_variable_length_quantity(int(node)))

    #logging.debug(f'oid_hex is {oid_hex.hex()}')
    return oid_hex


def get_tree_dict(Line):
    # returns a dict 

    oid_string = Line.split("=", 1)[0].strip()
    oid_hex = OID_to_hex(oid_string)
    #logging.debug (f"oid_string: {oid_string}")
    oid_type = Line.split("=", 1)[1].split(":", 1)[0].strip()

    #logging.debug (f"oid_type: {oid_type} hex: {oid_type.encode('utf-8').hex()} vartype: {type(oid_type)}")

    if oid_type == "STRING":
        oid_value = Line.split("=", 1)[1].split(":", 1)[1].strip().strip('\"')
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
        logging.warning(f"Unknown OID type: {oid_type}.")
        raise Exception

    # populate the response cache: 
    oid_package = assemble_oid_package(oid_hex, oid_type, oid_value)    


    #logging.debug (f"oid_value: {oid_value}")
    return {"oid_string": oid_string, "oid_hex": oid_hex, "oid_type": oid_type, "oid_value": oid_value, "oid_package": oid_package}


def assemble_oid_package(oid_hex, oid_type, oid_value):
    #  The oid package will be stored with the tree.  It is pre-calculated for speed.  It's construction and use is static.

    # Assemble the oid_value_package bytearray: type, length, and the value.
    oid_value_package = bytearray()

    if (oid_type=="endOfMibView"):  # this is really only used for dynamic calling of the assemble_oid_package, not the initial cache building
        oid_value_package.append(0x82)
        oid_value_package.append(0x00)

    elif ((isinstance(oid_value, int)) & (oid_type == "Gauge32")):
        encoder.start()
        encoder.write(oid_value)
        oid_value_package = encoder.output()
    
    elif ((isinstance(oid_value, int)) & (oid_type == "IpAddress")):
        oid_value_package.append(0x40) 
        oid_value_package.append(0x04)
        oid_value_package.extend(oid_value.to_bytes(4, 'big'))

    elif isinstance(oid_value, int):
        encoder.start()
        encoder.write(oid_value)
        oid_value_package = encoder.output()

    elif ((isinstance(oid_value, str)) & (oid_type == "STRING")):
        encoder.start()
        encoder.write(oid_value, nr=0x04)
        oid_value_package = encoder.output()

    elif ((isinstance(oid_value, str)) & (oid_type == "OID")):
        oid_value_package.append(0x06)
        oid_value_package.append(len(OID_to_hex(oid_value)))
        oid_value_package.extend(OID_to_hex(oid_value))
    
    elif isinstance(oid_value, str):
        encoder.start()
        encoder.write(oid_value, nr=0x04)
        oid_value_package = encoder.output()

    else: 
        logging.error("Unknown OID_Value encoding method.")
        raise Exception("Could not determine how to encode this oid_value.")

    #logging.debug(f'oid_value_package is {oid_value_package}')

    # assemble the total package:
    oid_package = bytearray()

    oid_package.append(0x06)  # 0x06 means this is an OID
    oid_package.extend(encode_variable_length(len(oid_hex)))  # length of the OID to follow
    oid_package.extend(bytes(oid_hex))  # the actual 1.3.6.....oid
    oid_package.extend(oid_value_package)  # the entire value package: value_type, value_length, value

    return oid_package

#def formulate_get_response(request_id, community, oid_hex, oid_value, oid_type):
def formulate_get_response(request_id, community, oid_package):
    # returns a prepared byte object for a non-final response to an SNMPwalk
    
    #if DEBUG: logging.debug(f'Stored oid type: {oid_type}.  Pythonic type of oid_value: {type(oid_value)}')


    ### LENGTHS ###
    ### LENGTHS ###
    ### LENGTHS ###
    
    # Initialise lengths to be built from the bottom up.
    if DEBUG: logging.debug("Initialise lengths")
    length_all = 0x0
    length_community = 0x0
    length_to_end1_response = 0x0
    length_to_end_binding_ONE = 0x0
    length_to_end_binding_ALL = 0x0
    length_to_end_of_oid = 0x0 
    #length_to_end4_value = 0x0  # not needed anymore due to ASN1



    # Encrich lengths from bottom up.
    running_total = 0
    if DEBUG: logging.debug('Enrich lengths from bottom up')
 
    # Reserving space for the oid_package as a whole
    running_total += len(oid_package)


    length_to_end_binding_ONE = running_total # length of variable-bindings ONE bytes remaining
    running_total += len(encode_variable_length(running_total))  # number of length bytes - could be a variable length if > 127
    running_total += 1  # variable binding number ONE:  0x30
    length_to_end_binding_ALL = running_total # length of variable-bindings ALL bytes remaining
    running_total += len(encode_variable_length(running_total))  # number of length bytes - could be a variable length if > 127 
    running_total += 1  # variable-bindings ALL : 0x30

    running_total += 6  # error overhead

    running_total += 4  # request ID , always 4 bytes
    running_total += 2  # request ID preamble 0x0204

    length_to_end1_response = running_total
    running_total += len(encode_variable_length(running_total))  # length byte placeholder 
    running_total += 1  # RESPONSE 0xA2
    
    length_community = len(community)
    running_total += len(community)
    running_total += len(encode_variable_length(length_community))  # demarc, length byte placeholder  
    running_total += 1  # community dmarc 0x04
    running_total += 3  # demarc 0x02, 0x01 bytelengths, 0x01 version
    length_all = running_total
    # Ignoring below remaining preamble:
    # length byte placeholder, does not count
    # 0x30 , start, does not count

    logging.debug(f'Running total of response size: {running_total}')

    ### FILL ###
    ### FILL ###
    ### FILL ###

    # Fill the template
    logging.debug('Filling the template')
    datafill = bytearray()  # a blank
    datafill.append(0x30)  # 1 byte, start. 
    
    logging.debug(f'encode is {encode_variable_length_quantity_allMSB1(length_all)} ')
    datafill.extend(encode_variable_length(length_all))  # variable length

    datafill.append(0x02)  # demarc, version
    datafill.append(0x01)  # demarc, length 01
    datafill.append(0x01)  # demarc, version 01

    datafill.append(0x04)  # community demarc 04
    datafill.append(length_community) # usually one byte, length to end of community string, ie. 0x06 for public
    datafill.extend(community.encode('latin-1'))  # variable, eg. public

    datafill.append(0xA2)  # indicates RESPONSE, A0 is get-request, A1 is get-next-request , A2 is get_response
    logging.debug(f'after 0xa2 length_to_end1_response is {length_to_end1_response} resultant is {encode_variable_length_quantity_allMSB1(length_to_end1_response)}')
    datafill.extend(encode_variable_length(length_to_end1_response))  # length of RESPONSE bytes remaining entirely

    datafill.append(0x02)  # request_id demarc
    datafill.append(0x04)  # static, to end of request_id
    datafill.extend(request_id)
    logging.debug(f'request_id:')
    if DEBUG: print_hex_nicely(request_id)
    datafill.append(0x02)  # no error
    datafill.append(0x01)  # no error
    datafill.append(0x00)  # no error
    datafill.append(0x02)  # error index 0
    datafill.append(0x01)  # error index 0
    datafill.append(0x00)  # error index 0
    datafill.append(0x30)  # variable-bindings
    datafill.extend(encode_variable_length(length_to_end_binding_ALL))  # length of variable-bindings bytes remaining
    datafill.append(0x30)  # variable-bindings
    datafill.extend(encode_variable_length(length_to_end_binding_ONE))  # length of variable-bindings bytes remaining

    # datafill.append(0x06)  # OID number one
    # datafill.append(length_to_end_of_oid)  # length of the OID to follow
    # datafill.extend(oid_hex)  # variable, the encoded oid bytes, eg 0x2b plus 6.1.2.1...  see RFC spec
    # datafill.extend(oid_value_package)

    datafill.extend(oid_package)

    logging.debug(f'Datafill As Prepared:')
    if DEBUG: print_hex_nicely(datafill)
    return(datafill)


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
            logging.debug(f'Community String: {community}')
            
        else: 
            raise Exception

        # request ID
        cursor = 6 + comm_length + 5

        request_id = bytearray(4)
        for i in range(0,4):
            request_id[i] = data[cursor + i]
        logging.info(f'Request ID: {int.from_bytes(request_id, "big")}')
        if DEBUG: print_hex_nicely(request_id)
        cursor += 4

        # Advance the cursor to the OID length definition, accounting for 11 bytes of unnecessary error codes and index.
        cursor += 11

        # oid_requested
        oid_len = data[cursor]
        cursor += 1

        oid_requested = bytearray(oid_len)
        for i in range(0, oid_len):
            oid_requested[i] = data[cursor + i]
        cursor += oid_len
        logging.debug(f'OID Requested: {oid_requested}') 
        if DEBUG: print_hex_nicely(oid_requested)

        return community, request_id, oid_requested

    except Exception as e:
        logging.error(f'Problem: {e}')


def formulate_end_of_mib(request_id, community, oid_hex, oid_value, oid_type):
    pass


def formulate_no_object_found(request_id, community, oid_hex, oid_value, oid_type):
    pass


def get_request_type(data):
    # Lookahead to determine the type of request.  Need to skep a variable length field to do it (community)
    # A0get-request A1get-next-request A2get-response

    if DEBUG: logging.debug('getting request type')

    #cursor skips to variable-length-integer-byte 
    cursor = 0 
    cursor += 6  # the 6th byte is the value we also want

    communitylength = data[cursor]
    if DEBUG: logging.debug(f'communitylength is {communitylength}')
    cursor += communitylength

    request_type = data[cursor + 1]  # the very next byte has the answers.
    if DEBUG: logging.debug(f'request type determined to be {hex(request_type)}')
    return request_type




## OID Tree Construction 
tree = []
count = 0
problems = 0
# Strips the newline character
for line in Lines:
    count += 1
    #if DEBUG: logging.debug("Importing Line{}: {}".format(count, line.strip()))
    try:
        tree.append(get_tree_dict(line))
    except:
        logging.info(f"Problem importing this line: {line}".strip())
        problems += 1

logging.info(f'Loaded file: problems: {problems} total reviewed: {count} tree size: {len(tree)}')


### Open a UDP socket


sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

logging.info(f"Socket opened.  Listening on {UDP_IP} port {UDP_PORT}")

##  Listen for a request and respond.

while True:
    data, addr = sock.recvfrom(1460) # buffer size is 1024 bytes
    
    # diagnostics
    logging.info("RECEIVED MESSAGE")

    # Validate the request 
    try: 
        if not request_valid:
            raise Exception("Request is Not Valid.")
        else:
            if DEBUG: logging.debug("Request is Valid.")
            pass

        # Extract the artifacts we need to construct a response
        community, request_id, oid_requested = extract_request_details(data)
        request_type = get_request_type(data)
        
        len_oid_requested = len(oid_requested)
        datafill = bytearray()
        tree_cursor = 0

        # get-request
        if request_type == 0xA0:

            found = False
            # Direct Match Shortcut
            for t in range(0,len(tree)):
                #search the tree elements for a dict for a direct match. 
                if tree[t]['oid_hex'] == oid_requested:
                    if DEBUG: logging.debug(f"Direct OID match at branch position {t}. ")
                    found = True
                    tree_cursor = t
                    break
                else:
                    pass

            if found:      
                datafill = formulate_get_response(request_id, community, tree[tree_cursor]['oid_package'])
                if DEBUG: logging.debug(f"Formulating Valid Response based on element {t} {tree[t]}")
            else:
                if DEBUG: logging.debug("Formulating OID NOT FOUND")
                #### does not exist yet
                endOfMibView_oid_package = assemble_oid_package(oid_requested,'endOfMibView', '')
                datafill = formulate_get_response(request_id, community, endOfMibView_oid_package)

        # get-next-request
        elif request_type == 0xA1:

            found = False
            # Direct Match Shortcut
            for t in range(0,len(tree)):
                #search the tree elements for a dict for a direct match. 
                if tree[t]['oid_hex'] == oid_requested:
                    if DEBUG: logging.debug(f"Direct OID match at branch position {t}. ")
                    found = True
                    tree_cursor = t + 1  # next in tree
                    break
                else:
                    pass

            if found:
                
                if ((tree_cursor) < len(tree)):
                    if DEBUG: logging.debug(f"Formulating Valid Response based on next element {tree_cursor} {tree[tree_cursor]}")
                    datafill = formulate_get_response(request_id, community, tree[tree_cursor]['oid_package'])                   
                else: 
                    # next record would be beyond the MIB
                    if DEBUG: logging.debug("Formulating endOfMibView")
                    # denote end of MIB by using the requested OID, and a value fill of 0x82 0x00
                    endOfMibView_oid_package = assemble_oid_package(oid_requested,'endOfMibView', '')
                    datafill = formulate_get_response(request_id, community, endOfMibView_oid_package)
                
            else:
                #### a direct match ooes not exist, let's find the closest.
        
                game_on = True
                tree_cursor = 0
                
                # compare the requested OID bytes with branch's bytes to the maximum depth of the first part of the matched bytes.
                while game_on:

                
                    # figure out how many bytes deep this comparison will be.
                    len_oid_branch = len(tree[tree_cursor]['oid_hex'])
                    if len_oid_branch < len_oid_requested:
                        # we don't want this record then... clearly wont be a match
                        #if DEBUG: logging.debug('length of branch is less than request.')
                        tree_cursor += 1
                    
                    else:
                        # length of branch is longer or equal to length of request.
                        # roll through the bytes sequentially and see how many matched bytes we have 
                        matches = 0
                        for current_depth in range(0, len_oid_requested):
                            
                            if tree[tree_cursor]['oid_hex'][current_depth] == oid_requested[current_depth]:
                                matches += 1
                            else:
                                break
                        
                        #logging.debug(f'matches: {matches} , len_oid_requested: {len_oid_requested}')
                        # if this matches the length required, then we have identified a candidate record.
                        if matches == len_oid_requested:
                            if DEBUG: logging.debug(f'Identified a prefix match.  Element {tree_cursor}')
                            
                            datafill = formulate_get_response(request_id, community, tree[tree_cursor]['oid_package'])
                            game_on = False
                        else:
                            tree_cursor += 1

                        if tree_cursor == (len(tree) - 1):
                            # we are at the end of the search.  Time to send back a specially crafted endOfMibView packet. 
                            # essentially repeating back the query with data 0x82 with 0x00 length
                            endOfMibView_oid_package = assemble_oid_package(oid_requested,'endOfMibView', '')
                            datafill = formulate_get_response(request_id, community, endOfMibView_oid_package)
                            game_on = False


                if DEBUG: logging.debug(f'Best match node depth: {matches} at tree cursor position {tree_cursor}')      

            # Sending a reply to client
            sock.sendto(datafill, addr)
            logging.info('Response sent to client')

        else: 
            raise Exception("OIDrage: Unknown or Unsupported request_type")

    except Exception as e:
        logging.error(f'Exception: {e}')
