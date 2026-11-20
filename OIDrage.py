# OIDrage.py
# Patrick Scott Best, 2022
# https://github.com/patrickscottbest/OIDrage

# Uses a snmpwalk text output to mimic an SNMP target.


from time import sleep, time
import socket
import os
import asn1.asn1 as asn1
import ipaddress  # python3.3 required
import argparse
import sys
import logging
from ieee754 import IEEE754

encoder = asn1.Encoder()

DEBUG = False
required_community = False

# Security / resource limits
MAX_REPETITIONS = 50
MAX_BULK_BYTES = 1400
MAX_MIMIC_BYTES = 50 * 1024 * 1024
MAX_MIMIC_LINES = 200000
MAX_SHORT_LEN = 127  # short-form BER length assumption


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


def need_bytes(data, offset, count=1):
    """Ensure data[offset:offset+count] is in range; raise ValueError if not."""
    if offset < 0 or count < 0 or offset + count > len(data):
        raise ValueError(
            f"Packet too short: need {count} byte(s) at offset {offset}, have {len(data)}"
        )


def coerce_int(value, name, default, minimum=None, maximum=None):
    """Coerce CLI/env value to int with optional bounds."""
    if value is None:
        value = default
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid {name}: {value!r}") from exc
    if minimum is not None and number < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {number}")
    if maximum is not None and number > maximum:
        raise ValueError(f"{name} must be <= {maximum}, got {number}")
    return number


def is_loopback_address(ip_string):
    try:
        return ipaddress.ip_address(ip_string).is_loopback
    except ValueError:
        return False


def community_policy_allows(bind_ip, community_required):
    """Non-loopback binds require an explicit community."""
    if community_required:
        return True
    return is_loopback_address(bind_ip)


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
    elif oid_type == "Gauge32":
        oid_value = int(Line.split("=", 1)[1].split(":")[1].strip())
    elif oid_type == "Gauge64":
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
            logging.warning("We do not know how to deal with this opaque value yet.")
            raise Exception("Unsupported Opaque subtype")
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


def formulate_get_response(request_version, request_id, community, oid_package):
    # returns a prepared byte object for a non-final response to an SNMPwalk

    # Initialise lengths to be built from the bottom up.
    length_all = 0x0
    length_community = 0x0
    length_to_end1_response = 0x0
    length_to_end_binding_ALL = 0x0

    # Enrich lengths from bottom up.
    running_total = 0
    if DEBUG:
        logging.debug('Enrich lengths from bottom up')

    # Reserving space for the oid_package as a whole
    running_total += len(oid_package)

    length_to_end_binding_ALL = encode_variable_length(running_total)  # length of variable-bindings ALL bytes remaining
    running_total += len(encode_variable_length(running_total))  # number of length bytes - could be a variable length if > 127
    running_total += 1  # variable-bindings ALL : 0x30

    running_total += 6  # error overhead

    running_total += len(request_id)  # request ID
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

    logging.debug(f'Completed templating lengths.  Running total of response size: {running_total}')

    # Fill the template
    logging.debug('Filling the template')
    datafill = bytearray()  # a blank
    datafill.append(0x30)  # 1 byte, start.

    datafill.extend(encode_variable_length(length_all))  # variable length

    datafill.append(0x02)  # demarc, version
    datafill.append(0x01)  # demarc, length 01
    datafill.append(request_version)  # demarc, version 00/01

    datafill.append(0x04)  # community demarc 04
    datafill.append(length_community)  # usually one byte, length to end of community string, ie. 0x06 for public
    datafill.extend(community.encode('latin-1'))  # variable, eg. public

    datafill.append(0xA2)  # indicates RESPONSE
    datafill.extend(encode_variable_length(length_to_end1_response))  # length of RESPONSE bytes remaining entirely

    datafill.append(0x02)  # request_id demarc
    datafill.append(len(request_id))  # length of request_id
    datafill.extend(request_id)
    logging.debug('request_id:')
    if DEBUG:
        print_hex_nicely(request_id)
    datafill.append(0x02)  # no error
    datafill.append(0x01)  # no error
    datafill.append(0x00)  # no error
    datafill.append(0x02)  # error index 0
    datafill.append(0x01)  # error index 0
    datafill.append(0x00)  # error index 0
    datafill.append(0x30)  # variable-bindings

    datafill.extend(length_to_end_binding_ALL)

    datafill.extend(oid_package)

    logging.debug('Datafill As Prepared:')
    if DEBUG:
        print_hex_nicely(datafill)
    return datafill


def request_valid(data):
    # Examines that a request is valid and returns BOOL
    try:
        need_bytes(data, 0, 5)
    except ValueError:
        return False

    # Require short-form top-level length (bit 7 clear) — matches historical parser.
    if data[1] & 0x80:
        return False

    if ((data[0] != 0x30)  # snmp request type
        | (data[2] != 0x2)  # version demarc
        | (data[3] != 0x1)):  # version length
        return False
    return True


def get_request_type(data):
    # Lookahead to determine the type of request.
    # Need to skip a variable length field to do it (community)
    # A0get-request A1get-next-request A2get-response A5get-bulk

    if DEBUG:
        logging.debug('get request type')

    need_bytes(data, 6, 1)
    cursor = 6  # community length byte (short-form assumption)

    communitylength = data[cursor]
    if communitylength > MAX_SHORT_LEN:
        raise ValueError("Community length exceeds short-form BER limit")
    cursor += 1
    need_bytes(data, cursor, communitylength)
    cursor += communitylength

    need_bytes(data, cursor, 1)
    request_type = data[cursor]  # PDU tag
    if DEBUG:
        logging.debug(f'request type determined to be {hex(request_type)}')
    return request_type


def extract_request_details(data):
    # Returns what is needed to reformulate a valid response.
    # Short-form BER lengths only (community / OID / request-id <= 127).

    max_repetitions = 0

    request_type = get_request_type(data)

    need_bytes(data, 4, 1)
    request_version = data[4]

    # Community string
    need_bytes(data, 5, 2)
    if data[5] != 4:  # demarc for community
        raise ValueError("demarc for community not found")

    comm_length = data[6]
    if comm_length > MAX_SHORT_LEN:
        raise ValueError("Community length exceeds short-form BER limit")
    need_bytes(data, 7, comm_length)
    community = "".join(chr(data[7 + i]) for i in range(comm_length))
    logging.debug("Community String: [redacted]")

    # After community: PDU tag, PDU length (short), then request-id INTEGER tag+len
    # Historical cursor: 6 + comm_length + 5 lands on first request-id content byte
    # Layout after community: [PDU][pdu_len][0x02][req_id_len][req_id...]
    cursor = 7 + comm_length
    need_bytes(data, cursor, 4)
    # cursor at PDU tag; skip PDU tag, PDU length, 0x02, req_id_len
    if data[cursor] not in (0xA0, 0xA1, 0xA5):
        # still allow other PDUs to be rejected later
        pass
    pdu_len = data[cursor + 1]
    if pdu_len & 0x80:
        raise ValueError("Long-form PDU length not supported")
    need_bytes(data, cursor + 2, 2)
    if data[cursor + 2] != 0x02:
        raise ValueError("Request ID INTEGER tag not found")
    request_id_length = data[cursor + 3]
    if request_id_length < 1 or request_id_length > MAX_SHORT_LEN:
        raise ValueError("Invalid request ID length")
    cursor = cursor + 4
    need_bytes(data, cursor, request_id_length)
    request_id = bytearray(data[cursor:cursor + request_id_length])
    if DEBUG:
        logging.debug(f'Request ID: {int.from_bytes(request_id, "big")}')
        print_hex_nicely(request_id)

    cursor += request_id_length

    # error-status INTEGER (3 bytes) + error-index/non-repeaters INTEGER (3) for get/getnext
    # for getBulk: non-repeaters then max-repetitions
    need_bytes(data, cursor, 6)
    # skip error-status (or non-repeaters): 02 01 XX
    cursor += 3
    # at max-repetitions / error-index value byte after 02 01
    if request_type == 0xA5:
        need_bytes(data, cursor, 3)
        if data[cursor] != 0x02 or data[cursor + 1] != 0x01:
            raise ValueError("max_repetitions INTEGER not found")
        max_repetitions = min(data[cursor + 2], MAX_REPETITIONS)
        cursor += 3
    else:
        cursor += 3  # skip error-index 02 01 XX

    # variable-bindings: 30 [len] then first binding 30 [len] 06 [oid_len] oid...
    need_bytes(data, cursor, 2)
    if data[cursor] != 0x30:
        raise ValueError("variable-bindings SEQUENCE not found")
    vb_len = data[cursor + 1]
    if vb_len & 0x80:
        raise ValueError("Long-form variable-bindings length not supported")
    cursor += 2

    need_bytes(data, cursor, 2)
    if data[cursor] != 0x30:
        raise ValueError("varbind SEQUENCE not found")
    binding_len = data[cursor + 1]
    if binding_len & 0x80:
        raise ValueError("Long-form varbind length not supported")
    cursor += 2

    need_bytes(data, cursor, 2)
    if data[cursor] != 0x06:
        raise ValueError("OID tag not found")
    oid_len = data[cursor + 1]
    if oid_len > MAX_SHORT_LEN:
        raise ValueError("OID length exceeds short-form BER limit")
    cursor += 2
    need_bytes(data, cursor, oid_len)
    oid_requested = bytearray(data[cursor:cursor + oid_len])
    logging.debug(f'OID Requested length={oid_len}')
    if DEBUG:
        print_hex_nicely(oid_requested)

    return (
        community,
        request_id,
        request_type,
        oid_requested,
        max_repetitions,
        request_version
    )


def build_bulk_oid_package(tree, tree_cursor, max_repetitions, max_bytes=MAX_BULK_BYTES):
    """Concatenate oid_packages with tree and size bounds."""
    reps = max(0, min(int(max_repetitions), MAX_REPETITIONS))
    rep_oid_package = bytearray()
    for rep in range(reps):
        index = tree_cursor + rep
        if index >= len(tree):
            logging.warning('Response package would exceed tree nodes available')
            break
        next_pkg = tree[index]['oid_package']
        if len(rep_oid_package) + len(next_pkg) > max_bytes:
            logging.warning('Response package would be too large for full max_repetition')
            break
        rep_oid_package.extend(next_pkg)
    return rep_oid_package


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

    return found, tree_cursor


def resolve_inputfile(path):
    if path is None:
        return None
    if '\x00' in path:
        raise ValueError("INPUTFILE must not contain NUL bytes")
    resolved = os.path.abspath(path)
    cwd = os.path.abspath(os.getcwd())
    try:
        common = os.path.commonpath([cwd, resolved])
    except ValueError:
        common = None
    if common != cwd:
        logging.warning(f"INPUTFILE is outside the working directory: {resolved}")
    return resolved


def load_mimic_tree(inputfile):
    """Load and parse a mimic walk file into a tree list."""
    resolved = resolve_inputfile(inputfile)
    size = os.path.getsize(resolved)
    if size > MAX_MIMIC_BYTES:
        raise ValueError(
            f"Mimic file too large: {size} bytes (max {MAX_MIMIC_BYTES})"
        )

    logging.info(f"Opening Mimic File {resolved}")
    with open(resolved, 'r', encoding='utf-8', errors='replace') as file1:
        Lines = file1.readlines()

    if len(Lines) > MAX_MIMIC_LINES:
        raise ValueError(
            f"Mimic file has too many lines: {len(Lines)} (max {MAX_MIMIC_LINES})"
        )

    tree = []
    count = 0
    problems = 0
    for line in Lines:
        count += 1
        try:
            if not line.startswith("#") and line.strip():
                tree.append(get_tree_dict(line))
        except Exception as e:
            logging.warning(f"Problem: {e} while importing this line: {line}".strip())
            problems += 1

    logging.info(
        f'Loaded mimic file. problems: {problems}, total reviewed: {count}, tree size: {len(tree)}'
    )
    return tree


def main(args):
    global required_community

    if args.inputfile is None:
        args.inputfile = os.getenv("INPUTFILE", default="mimic.txt")
    if args.ipaddress is None:
        args.ipaddress = os.getenv("IPADDRESS", default="127.0.0.1")
    if args.port is None:
        args.port = os.getenv("PORT", default=161)
    if args.delay is None:
        args.delay = os.getenv("DELAY", default=0)

    args.port = coerce_int(args.port, "PORT", 161, minimum=1, maximum=65535)
    args.delay = coerce_int(args.delay, "DELAY", 0, minimum=0, maximum=60000)

    if not community_policy_allows(args.ipaddress, required_community):
        logging.error(
            "Refusing to bind non-loopback address without a required community. "
            "Set -c/--community or COMMUNITY, or bind 127.0.0.1."
        )
        return 2

    tree = load_mimic_tree(args.inputfile)

    # Open a UDP socket
    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP
    sock.bind((args.ipaddress, args.port))
    logging.info(f"Socket opened.  Listening {args.ipaddress} port {args.port}")

    last_activity_log_time = 0

    # Listen for a request and respond.
    while True:
        try:
            data, addr = sock.recvfrom(1460)
            # Log activity if it has been quiet for a while
            current_time = time()
            if current_time - last_activity_log_time > 5:  # 5 second cooldown
                logging.info(f"Request received from {addr[0]}:{addr[1]}")
                last_activity_log_time = current_time
        except Exception as e:
            logging.warning(f'Problem with socket: {e}')
            continue

        logging.debug("RECEIVED MESSAGE")

        try:
            # Validate the request
            if not request_valid(data):
                raise Exception("Request is Not Valid.")
            if DEBUG:
                logging.debug("Request is Valid.")

            # Extract the artifacts we may need to construct a response
            community, request_id, request_type, oid_requested, max_repetitions, request_version = extract_request_details(data)

            # See if mandatory community string was set.
            if required_community:
                if community != args.community:
                    raise ValueError("Community String Incorrect.")

            datafill = bytearray()
            tree_cursor = 0

            if request_type == 0xA0:  # get-request

                found, tree_cursor = find_direct_match(tree, oid_requested)

                if found:
                    datafill = formulate_get_response(request_version, request_id, community, tree[tree_cursor]['oid_package'])
                    if DEBUG:
                        logging.debug(f"Formulating Valid Response based on element {tree_cursor}")
                else:
                    if DEBUG:
                        logging.debug("Formulating NO SUCH OBJECT")
                    noSuchObject_oid_package = assemble_oid_package(oid_requested, 'noSuchObject', '')
                    datafill = formulate_get_response(request_version, request_id, community, noSuchObject_oid_package)

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
                    if tree_cursor < len(tree):
                        if DEBUG:
                            logging.debug(f"Formulating Response based on next element {tree_cursor}")
                        datafill = formulate_get_response(request_version, request_id, community, tree[tree_cursor]['oid_package'])
                    else:
                        if DEBUG:
                            logging.debug("Formulating endOfMibView")
                        endOfMibView_oid_package = assemble_oid_package(oid_requested, 'endOfMibView', '')
                        datafill = formulate_get_response(request_version, request_id, community, endOfMibView_oid_package)
                else:
                    found, tree_cursor = find_closest_match(tree, oid_requested)

                    if found:
                        datafill = formulate_get_response(request_version, request_id, community, tree[tree_cursor]['oid_package'])
                    else:
                        endOfMibView_oid_package = assemble_oid_package(oid_requested, 'endOfMibView', '')
                        datafill = formulate_get_response(request_version, request_id, community, endOfMibView_oid_package)

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
                    if tree_cursor < len(tree):
                        if DEBUG:
                            logging.debug(f"Formulating Response based on next element {tree_cursor}")
                        rep_oid_package = build_bulk_oid_package(tree, tree_cursor, max_repetitions)
                        if len(rep_oid_package) == 0:
                            endOfMibView_oid_package = assemble_oid_package(oid_requested, 'endOfMibView', '')
                            datafill = formulate_get_response(request_version, request_id, community, endOfMibView_oid_package)
                        else:
                            datafill = formulate_get_response(request_version, request_id, community, rep_oid_package)
                    else:
                        if DEBUG:
                            logging.debug("Formulating endOfMibView")
                        endOfMibView_oid_package = assemble_oid_package(oid_requested, 'endOfMibView', '')
                        datafill = formulate_get_response(request_version, request_id, community, endOfMibView_oid_package)
                else:
                    found, tree_cursor = find_closest_match(tree, oid_requested)

                    if found:
                        rep_oid_package = build_bulk_oid_package(tree, tree_cursor, max_repetitions)
                        if len(rep_oid_package) == 0:
                            endOfMibView_oid_package = assemble_oid_package(oid_requested, 'endOfMibView', '')
                            datafill = formulate_get_response(request_version, request_id, community, endOfMibView_oid_package)
                        else:
                            datafill = formulate_get_response(request_version, request_id, community, rep_oid_package)
                    else:
                        endOfMibView_oid_package = assemble_oid_package(oid_requested, 'endOfMibView', '')
                        datafill = formulate_get_response(request_version, request_id, community, endOfMibView_oid_package)

                sleep(args.delay * 0.001)  # configurable
                sock.sendto(datafill, addr)
                logging.debug('Response sent to client')
            else:
                raise Exception("OIDrage: Unknown or Unsupported request_type")

        except Exception as e:
            logging.error(f'Main Loop Problem: {e}')


def configure_runtime(args):
    """Apply debug/community settings from CLI/env. Returns nothing; sets globals."""
    global DEBUG, required_community

    DEBUG = bool(args.debug or os.getenv("DEBUG"))

    if DEBUG:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
            force=True,
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
            force=True,
        )

    if args.community is None:
        args.community = os.getenv('COMMUNITY', default=None)
        required_community = args.community is not None
    else:
        required_community = True
    logging.info(f'Community string required? {required_community}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OIDrage SNMPd Mimic Server by Patrick Scott Best')
    # defaults set in main after ENV eval
    parser.add_argument('-f', '--inputfile', type=str, help="Input file. [mimic.txt]", default=None)
    parser.add_argument('-i', '--ipaddress', type=str, help="IP Address.  [127.0.0.1]", default=None)
    parser.add_argument('-p', '--port', type=int, help="UDP port number to bind to. [161]", default=None)
    parser.add_argument('-d', '--delay', type=int, help="Response delay, in milliseconds.  [0]", default=None)
    parser.add_argument('-c', '--community', type=str, help="Require a specific community string from client. [*]", default=None)
    parser.add_argument('-D', '--debug', action='store_true', help="Debug")

    args = parser.parse_args()
    configure_runtime(args)
    logging.info("OIDrage by Patrick Scott Best")
    if DEBUG:
        logging.debug("DEBUG is enabled.")
    sys.exit(main(args) or 0)
