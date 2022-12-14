# OIDrage.py
# Patrick Scott Best, 2022
# https://github.com/patrickscottbest/OIDrage

# Uses a snmpwalk text output to mimic an SNMP target.


from time import sleep
import socket
import os
import asn1.asn1 as asn1
import ipaddress  # python3.3 required
import argparse
import sys
import logging
from ieee754 import IEEE754

encoder = asn1.Encoder()

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")


def print_hex_nicely(data):

    # a nice debug way to print out HEX
    # similar to wireshark packet bytes

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


def float_to_bin(num):
    return bin(struct.unpack('!I', struct.pack('!f', num))[0])[2:].zfill(32)

def bin_to_float(binary):
    return struct.unpack('!f',struct.pack('!I', int(binary, 2)))[0]


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


def encode_variable_length_quantity(v: int) -> list:
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


def OID_to_hex(oid_string):
    # takes an entire oid string and encodes an SNMP compliant hex chain

    # if not oid_string.startswith(".1.3.6"):
    #     # this might be ok
    #     logging.debug(f"OID does not start with .1.3.6 - oid: {oid_string}")

    oid_hex = bytearray()
    oid_hex.extend(b'\x2b')
    oid_array = oid_string.split('.')
    oid_array.pop(0)  # remove first blank
    oid_array.pop(0)  # next two are forgone as 0x2B
    oid_array.pop(0)  # next two are forgone as 0x2B

    for node in oid_array:
        # special handling for nodes > 127
        if (int(node)) < 128:
            oid_hex.extend(int(node).to_bytes(1, 'big'))
        else:
            oid_hex.extend(encode_variable_length_quantity(int(node)))

    return oid_hex


def get_tree_dict(Line):
    # returns a dict

    oid_string = Line.split("=", 1)[0].strip()
    oid_hex = OID_to_hex(oid_string)
    oid_type = Line.split("=", 1)[1].split(":", 1)[0].strip()

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
    elif oid_type == "Opaque":
        # https://stackoverflow.com/questions/35276556/snmpsharpnet-opaque-float
        # IEEE 754 32-bit float
        opaque_value = Line.split("=", 1)[1].split(":", 1)[1].strip()
        if opaque_value.split(":")[0] == "Float":
            float_value = float(opaque_value.split(":")[1].strip())
            ieee_float = IEEE754(float_value)
            oid_value = bytearray()
            oid_value.append(0x04)
            oid_value.extend(ieee_float)
        else:
            logging.warning(f"We do not know how to deal with this opaque value yet.")
        pass
    elif oid_type == "\"\"":
        oid_type = "_none_"
        oid_value = ""
    else:
        logging.warning(f"Unknown OID type: {oid_type}")
        raise Exception

    # populate the response cache: 
    oid_package = assemble_oid_package(oid_hex, oid_type, oid_value)    
    return {"oid_string": oid_string,
            "oid_hex": oid_hex,
            "oid_type": oid_type,
            "oid_value": oid_value,
            "oid_package": oid_package}


def assemble_oid_package(oid_hex, oid_type, oid_value):
    # The oid_package will be stored with the tree.
    # Pre-calculated for speed. Is static.

    # Assemble the oid_value_package bytearray: type, length, and the value.
    oid_value_package = bytearray()

    if (oid_type == "endOfMibView"):  # special, only used for dynamic calling of the assemble_oid_package, not the initial cache building
        oid_value_package.append(0x82)
        oid_value_package.append(0x00)

    elif (oid_type == "noSuchObject"):  # special, only used for dynamic calling of the assemble_oid_package, not the initial cache building
        oid_value_package.append(0x80)
        oid_value_package.append(0x00)

    elif (oid_type == "Opaque"):
        oid_value_package.append(0x44)
        oid_value_package.append(0x07)
        oid_value_package.append(0x9F)
        oid_value_package.append(0x78)
        oid_value_package.extend(oid_value)

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

    # assemble the total package:
    oid_package = bytearray()

    oid_package.append(0x30)  # preamble

    # length of grouping to follow
    oid_package.extend(
        encode_variable_length(
            1 +  # 0x06
            len(encode_variable_length(len(oid_hex))) +
            len(oid_hex) +
            len(oid_value_package)
        )
    )

    oid_package.append(0x06)  # 0x06 means this is an OID
    oid_package.extend(encode_variable_length(len(oid_hex)))  # length of the OID to follow
    oid_package.extend(bytes(oid_hex))  # the actual 1.3.6.....oid
    oid_package.extend(oid_value_package)  # (value_type, value_length, value)

    return oid_package


def formulate_get_response(request_id, community, oid_package):
    # returns a prepared byte object for a non-final response to an SNMPwalk

    # LENGTHS ###
    # LENGTHS ###
    # LENGTHS ###

    # Initialise lengths to be built from the bottom up.
    length_all = 0x0
    length_community = 0x0
    length_to_end1_response = 0x0
    length_to_end_binding_ALL = 0x0
    length_to_end_of_oid = 0x0
    # length_to_end4_value = 0x0  # not needed anymore due to ASN1

    # Encrich lengths from bottom up.
    running_total = 0
    if DEBUG:
        logging.debug('Enrich lengths from bottom up')

    # Reserving space for the oid_package as a whole
    running_total += len(oid_package)

    # fixed it... 
    length_to_end_binding_ALL = encode_variable_length(running_total)  # length of variable-bindings ALL bytes remaining
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

    logging.debug(f'Completed templating lengths.  Running total of response size: {running_total}')

    # FILL ###
    # FILL ###
    # FILL ###

    # Fill the template
    logging.debug('Filling the template')
    datafill = bytearray()  # a blank
    datafill.append(0x30)  # 1 byte, start.

    datafill.extend(encode_variable_length(length_all))  # variable length

    datafill.append(0x02)  # demarc, version
    datafill.append(0x01)  # demarc, length 01
    datafill.append(0x01)  # demarc, version 01

    datafill.append(0x04)  # community demarc 04
    datafill.append(length_community)  # usually one byte, length to end of community string, ie. 0x06 for public
    datafill.extend(community.encode('latin-1'))  # variable, eg. public

    datafill.append(0xA2)  # indicates RESPONSE
    datafill.extend(encode_variable_length(length_to_end1_response))  # length of RESPONSE bytes remaining entirely

    datafill.append(0x02)  # request_id demarc
    datafill.append(0x04)  # static, to end of request_id
    datafill.extend(request_id)
    logging.debug(f'request_id:')
    if DEBUG:
        print_hex_nicely(request_id)
    datafill.append(0x02)  # no error
    datafill.append(0x01)  # no error
    datafill.append(0x00)  # no error
    datafill.append(0x02)  # error index 0
    datafill.append(0x01)  # error index 0
    datafill.append(0x00)  # error index 0
    datafill.append(0x30)  # variable-bindings

    # length of all variable-bindings bytes remaining
    ### something should be 81, then 91 
    datafill.extend(length_to_end_binding_ALL)

    datafill.extend(oid_package)

    logging.debug(f'Datafill As Prepared:')
    if DEBUG:
        print_hex_nicely(datafill)
    return datafill


def request_valid(data):
    # Examines that a request is valid and returns BOOL
    # <FALLTHROUGH>

    if ((data[0] != 0x30)  # snmp request type
        | (data[2] != 0x2)  # version demarc
        | (data[3] != 0x1)):  # version
        return False
    else:
        return True


def extract_request_details(data):
    # Returns what is needed to reformulate a valid response.
    # binding assumption - requested OID length never > 127
    # binding assumption - requested community length never > 127

    try:
        # only relevant for bulk requests
        max_repetitions = 0

        request_type = get_request_type(data)

        # Community string
        if data[5] == 4:  # demarc for community
            comm_length = data[6]
            community = ""
            for i in range(comm_length):
                community += chr(data[7+i])
            logging.debug(f'Community String: {community}')

        else:
            raise Exception("demarc for community not found")

        # Request ID
        cursor = 6 + comm_length + 5

        request_id = bytearray(4)
        for i in range(0, 4):
            request_id[i] = data[cursor + i]
        if DEBUG:
            logging.debug(f'Request ID: {int.from_bytes(request_id, "big")}')
            print_hex_nicely(request_id)

        # advance beyond the request_id
        cursor += 4

        # advance cursor to position for max_repetitions
        cursor += 5
        if request_type == 0xA5:
            # just in case, otherwise throw away
            max_repetitions = data[cursor]

        # advance cursor to the OID length definition
        cursor += 6

        # oid_requested
        oid_len = data[cursor]
        cursor += 1

        oid_requested = bytearray(oid_len)
        for i in range(0, oid_len):
            oid_requested[i] = data[cursor + i]
        cursor += oid_len
        logging.debug(f'OID Requested: {oid_requested}')
        if DEBUG:
            print_hex_nicely(oid_requested)

        return (
            community,
            request_id,
            request_type,
            oid_requested,
            max_repetitions
        )

    except Exception as e:
        logging.error(f'Extraction Problem: {e}')


def get_request_type(data):
    # Lookahead to determine the type of request.
    # Need to skip a variable length field to do it (community)
    # A0get-request A1get-next-request A2get-response

    if DEBUG:
        logging.debug('get request type')

    # cursor skips to variable-length-integer-byte
    cursor = 0
    cursor += 6  # the 6th byte is the value we also want

    communitylength = data[cursor]
    cursor += communitylength

    request_type = data[cursor + 1]  # the very next byte has the answers.
    if DEBUG:
        logging.debug(f'request type determined to be {hex(request_type)}')
    return request_type


def find_closest_match(tree, oid_requested):
    # a direct match does not exist, let's find the closest.
    if DEBUG:
        logging.debug('Find closest match.')

    len_oid_requested = len(oid_requested)
    
    found = False
    tree_cursor = 0

    # compare the requested OID bytes with branch's bytes to the maximum depth of the first part of the matched bytes.
    for branch in range(0, len(tree)):

        # figure out how many bytes deep this comparison is
        len_oid_branch = len(tree[branch]['oid_hex'])

        if len_oid_branch < len_oid_requested:
            # we don't want this record. not a match.
            pass
        else:
            # length of branch is longer or equal to length of request.
            # roll through the bytes sequentially and see how many match
            matches = 0
            for current_depth in range(0, len_oid_requested):

                if tree[branch]['oid_hex'][current_depth] == oid_requested[current_depth]:
                    matches += 1
                else:
                    break

            # identified a candidate record.
            if matches == len_oid_requested:
                if DEBUG:
                    logging.debug(f'Identified a prefix match. Element {branch}')
                found = True
                tree_cursor = branch
                break
            else:
                pass

    if DEBUG:
        logging.debug(f'found: {found}, cursor: {tree_cursor}')      

    return found, tree_cursor


def find_direct_match(tree, oid_requested):
    # Direct Match Shortcut
    
    found = False
    tree_cursor = 0

    for t in range(0, len(tree)):
        # search tree elements for a dict for direct match.
        if tree[t]['oid_hex'] == oid_requested:
            if DEBUG:
                logging.debug(f"Direct OID match at position {t}. ")
            found = True
            tree_cursor = t
            break
        else:
            pass

    return found, tree_cursor


def main(args):

    if args.inputfile is None:
        args.inputfile = os.getenv("INPUTFILE", default="mimic.txt")
    if args.ipaddress is None:
        args.ipaddress = os.getenv("IPADDRESS", default="127.0.0.1")
    if args.port is None:
        args.port = os.getenv("PORT", default=161)
    if args.delay is None:
        args.delay = os.getenv("DELAY", default=0)

    logging.info(f"Opening Mimic File {args.inputfile}")
    file1 = open(args.inputfile, 'r')
    Lines = file1.readlines()

    # OID Tree Construction
    tree = []
    count = 0
    problems = 0
    # Strips the newline character
    for line in Lines:
        count += 1
        try:
            if not line.startswith("#"):
                tree.append(get_tree_dict(line))
        except Exception as e:
            logging.warning(f"Problem: {e} while importing this line: {line}".strip())
            problems += 1

    logging.info(f'Loaded mimic file. problems: {problems}, total reviewed: {count}, tree size: {len(tree)}')

    # Open a UDP socket
    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP
    sock.bind((args.ipaddress, args.port))
    logging.info(f"Socket opened.  Listening {args.ipaddress} port {args.port}")

    # Listen for a request and respond.

    while True:
        try:
            data, addr = sock.recvfrom(1460)  # buffer size is 1024 bytes
        except Exception as e:
            logging.warning(f'Problem with socket: {e}')

        logging.debug("RECEIVED MESSAGE")

        try:
            # Validate the request
            if not request_valid(data):
                raise Exception("Request is Not Valid.")
            else:
                if DEBUG:
                    logging.debug("Request is Valid.")
                pass

            # Extract the artifacts we may need to construct a response
            community, request_id, request_type, oid_requested, max_repetitions = extract_request_details(data)

            # See if mandatory community string was set.
            if required_community:
                if not (community == args.community):
                    raise ValueError("Community String Incorrect.")
            else:
                pass

            len_oid_requested = len(oid_requested)
            datafill = bytearray()
            tree_cursor = 0

            if request_type == 0xA0:  # get-request

                found, tree_cursor = find_direct_match(tree, oid_requested)

                if found:
                    datafill = formulate_get_response(request_id, community, tree[tree_cursor]['oid_package'])
                    if DEBUG:
                        logging.debug(f"Formulating Valid Response based on element {tree_cursor} {tree[tree_cursor]}")
                else:
                    if DEBUG: logging.debug("Formulating NO SUCH OBJECT")
                    noSuchObject_oid_package = assemble_oid_package(oid_requested,'noSuchObject', '')
                    datafill = formulate_get_response(request_id, community, noSuchObject_oid_package)

                sleep(args.delay * 0.001)  # configurable
                sock.sendto(datafill, addr)
                logging.debug('Response sent to client')

            elif request_type == 0xA1:  # get-next-request

                found = False

                # Requesting .1 or .1.3 Shortcut
                if oid_requested == bytearray([0x01]):
                    logging.debug("Shortcut for .1 - First node")
                    found = True
                    tree_cursor = 0
                elif oid_requested == bytearray([0x2b]):
                    logging.debug("Shortcut for .1.3 - First node")
                    found = True
                    tree_cursor = 0
                else:
                    found, tree_cursor = find_direct_match(tree, oid_requested)
                    tree_cursor += 1  # increment, this is a get-next-request

                if found:
                    if ((tree_cursor) < len(tree)):
                        if DEBUG:
                            logging.debug(f"Formulating Response based on next element {tree_cursor} {tree[tree_cursor]}")
                        datafill = formulate_get_response(request_id, community, tree[tree_cursor]['oid_package'])                   
                    else:
                        # next record would be beyond the MIB
                        if DEBUG:
                            logging.debug("Formulating endOfMibView")
                        # denote end of MIB by using the requested OID, and a value fill of 0x82 0x00
                        endOfMibView_oid_package = assemble_oid_package(oid_requested, 'endOfMibView', '')
                        datafill = formulate_get_response(request_id, community, endOfMibView_oid_package)
                else:
                    # a direct match does not exist, let's find the closest.

                    found, tree_cursor = find_closest_match(tree, oid_requested)

                    if found:
                        datafill = formulate_get_response(request_id, community, tree[tree_cursor]['oid_package'])
                    else:
                        # at the end of the search.
                        # respond with a specially crafted endOfMibView packet.
                        # repeat back the query with data 0x82 with 0x00 length
                        endOfMibView_oid_package = assemble_oid_package(oid_requested, 'endOfMibView', '')
                        datafill = formulate_get_response(request_id, community, endOfMibView_oid_package)

                # Sending a reply to client
                sleep(args.delay * 0.001)  # configurable
                sock.sendto(datafill, addr)
                logging.debug('Response sent to client')

            # getBulkRequest
            elif request_type == 0xA5:

                found = False

                # Requesting .1 or .1.3 Shortcut
                if oid_requested == bytearray([0x01]):
                    logging.debug("Shortcut for .1 - First node")
                    found = True
                    tree_cursor = 0
                elif oid_requested == bytearray([0x2b]):
                    logging.debug("Shortcut for .1.3 - First node")
                    found = True
                    tree_cursor = 0
                else:
                    found, tree_cursor = find_direct_match(tree, oid_requested)
                    tree_cursor += 1  # increment, response starts next entry

                if found:
                    if ((tree_cursor) < len(tree)):
                        if DEBUG:
                            logging.debug(f"Formulating Response based on next element {tree_cursor} {tree[tree_cursor]}")
                        rep_oid_package = bytearray()
                        for rep in range(0, max_repetitions):
                            rep_oid_package.extend(
                                tree[tree_cursor + rep]['oid_package'])
                        datafill = formulate_get_response(request_id, community, rep_oid_package)
                    else: 
                        # next record would be beyond the MIB
                        if DEBUG: logging.debug("Formulating endOfMibView")
                        # denote end of MIB by using the requested OID, and a value fill of 0x82 0x00
                        endOfMibView_oid_package = assemble_oid_package(oid_requested,'endOfMibView', '')
                        datafill = formulate_get_response(request_id, community, endOfMibView_oid_package)
                else:
                    # a direct match does not exist, let's find the closest.

                    found, tree_cursor = find_closest_match(tree, oid_requested)

                    if found:
                        rep_oid_package = bytearray()
                        for rep in range(0, max_repetitions):
                            # careful not to extend the bounds of packet size or nodes available
                            if len(rep_oid_package) > 1400:
                                logging.warning('Response package would be too large for full max_repetition')
                                break
                            elif (tree_cursor + rep) >= len(tree):
                                logging.warning('Response package would exceed tree nodes available')
                                break
                            else:
                                rep_oid_package.extend(
                                    tree[tree_cursor + rep]['oid_package'])
                        datafill = formulate_get_response(request_id, community, rep_oid_package)

                    else:
                        # we are at the end of the search.  Time to send back a specially crafted endOfMibView packet. 
                        # essentially repeating back the query with data 0x82 with 0x00 length
                        endOfMibView_oid_package = assemble_oid_package(oid_requested,'endOfMibView', '')
                        datafill = formulate_get_response(request_id, community, endOfMibView_oid_package)

                # Sending a reply to client
                sleep(args.delay * 0.001)  # configurable
                sock.sendto(datafill, addr)
                logging.debug('Response sent to client')
            else:
                raise Exception("OIDrage: Unknown or Unsupported request_type")

        except Exception as e:
            logging.error(f'Main Loop Problem: {e}')


if __name__ == '__main__':
    logging.info("OIDrage by Patrick Scott Best")
    parser = argparse.ArgumentParser(description='OIDrage SNMPd Mimic Server by Patrick Scott Best')
    # defaults set in main after ENV eval
    parser.add_argument('-f', '--inputfile', type=str, help="Input file. [mimic.txt]", default=None)
    parser.add_argument('-i', '--ipaddress', type=str, help="IP Address.  [127.0.0.1]", default=None)
    parser.add_argument('-p', '--port', type=int, help="UDP port number to bind to. [161]", default=None)
    parser.add_argument('-d', '--delay', type=int, help="Response delay, in milliseconds.  [0]", default=None)
    parser.add_argument('-c', '--community', type=str, help="Require a specific community string from client. [*]", default=None)
    parser.add_argument('-D', '--debug', type=bool, help="Debug", default=None)

    args = parser.parse_args()

    required_community = False
    DEBUG = False

    # cli priority, then ENV, then default
    if args.debug is None:
        args.debug = os.getenv("DEBUG", default=None)
        if args.debug is None:
            DEBUG = False
            logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
        else:
            DEBUG = True
            logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    else:
        DEBUG = True
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")

    if DEBUG:
        logging.debug("DEBUG is enabled.")

    if args.community is None:
        args.community = os.getenv('COMMUNITY', default=None)
        if args.community is None:
            #  bool quicker to eval
            required_community = False
        else:
            required_community = True
    logging.info(f'Community string required? {required_community}')

    sys.exit(main(args))
else:
    logging.error("OIDrage must be called from command line.")
    raise Exception("OIDrage must be called from command line.")
