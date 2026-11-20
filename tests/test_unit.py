import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import OIDrage as oidrage
from snmp_test_helpers import build_snmp_pdu, oid_sysdescr_hex


FIXTURE = os.path.join(os.path.dirname(__file__), 'fixtures', 'tiny_mimic.txt')


class TestCoercionAndPolicy(unittest.TestCase):
    def test_coerce_int_env_string(self):
        self.assertEqual(oidrage.coerce_int('1161', 'PORT', 161, 1, 65535), 1161)

    def test_coerce_int_rejects_garbage(self):
        with self.assertRaises(ValueError):
            oidrage.coerce_int('nope', 'PORT', 161)

    def test_loopback_allows_open_community(self):
        self.assertTrue(oidrage.community_policy_allows('127.0.0.1', False))
        self.assertTrue(oidrage.community_policy_allows('::1', False))

    def test_non_loopback_requires_community(self):
        self.assertFalse(oidrage.community_policy_allows('0.0.0.0', False))
        self.assertFalse(oidrage.community_policy_allows('192.168.1.10', False))
        self.assertTrue(oidrage.community_policy_allows('0.0.0.0', True))


class TestEncodeAndTree(unittest.TestCase):
    def test_oid_to_hex_sysdescr(self):
        self.assertEqual(
            bytes(oidrage.OID_to_hex('.1.3.6.1.2.1.1.1.0')),
            bytes(oid_sysdescr_hex()),
        )

    def test_load_tiny_mimic(self):
        tree = oidrage.load_mimic_tree(FIXTURE)
        self.assertGreaterEqual(len(tree), 5)
        self.assertEqual(tree[0]['oid_type'], 'STRING')
        self.assertIn(b'OIDrage test device', tree[0]['oid_package'])

    def test_get_tree_dict_counter(self):
        entry = oidrage.get_tree_dict(
            '.1.3.6.1.2.1.2.2.1.10.1 = Counter32: 42\n'
        )
        self.assertEqual(entry['oid_type'], 'Counter32')
        self.assertEqual(entry['oid_value'], 42)


class TestRequestParsing(unittest.TestCase):
    def test_request_valid_accepts_get(self):
        pkt = build_snmp_pdu('public', oid_sysdescr_hex())
        self.assertTrue(oidrage.request_valid(pkt))

    def test_request_valid_rejects_short(self):
        self.assertFalse(oidrage.request_valid(b'\x30\x01'))

    def test_request_valid_rejects_long_form_length(self):
        # 0x81 would be long-form length marker in byte 1
        pkt = bytearray(build_snmp_pdu('public', oid_sysdescr_hex()))
        pkt[1] = 0x81
        self.assertFalse(oidrage.request_valid(bytes(pkt)))

    def test_extract_get_details(self):
        req_id = b'\x11\x22\x33\x44'
        pkt = build_snmp_pdu('public', oid_sysdescr_hex(), request_id=req_id)
        community, got_id, req_type, oid, max_rep, version = oidrage.extract_request_details(pkt)
        self.assertEqual(community, 'public')
        self.assertEqual(bytes(got_id), req_id)
        self.assertEqual(req_type, 0xA0)
        self.assertEqual(bytes(oid), bytes(oid_sysdescr_hex()))
        self.assertEqual(max_rep, 0)
        self.assertEqual(version, 1)

    def test_extract_getbulk_clamps_repetitions(self):
        pkt = build_snmp_pdu(
            'public', oid_sysdescr_hex(), pdu_type=0xA5, max_repetitions=255
        )
        _, _, req_type, _, max_rep, _ = oidrage.extract_request_details(pkt)
        self.assertEqual(req_type, 0xA5)
        self.assertEqual(max_rep, oidrage.MAX_REPETITIONS)

    def test_extract_rejects_truncated(self):
        pkt = build_snmp_pdu('public', oid_sysdescr_hex())
        with self.assertRaises(ValueError):
            oidrage.extract_request_details(pkt[:10])


class TestBulkBuilder(unittest.TestCase):
    def setUp(self):
        self.tree = oidrage.load_mimic_tree(FIXTURE)

    def test_bulk_respects_tree_end(self):
        # start near end with huge repetitions
        start = len(self.tree) - 2
        pkg = oidrage.build_bulk_oid_package(self.tree, start, 255)
        # only 2 nodes remain
        expected = bytearray()
        expected.extend(self.tree[start]['oid_package'])
        expected.extend(self.tree[start + 1]['oid_package'])
        self.assertEqual(pkg, expected)

    def test_bulk_respects_byte_cap(self):
        pkg = oidrage.build_bulk_oid_package(
            self.tree, 0, 50, max_bytes=40
        )
        self.assertLessEqual(len(pkg), 40)
        self.assertGreater(len(pkg), 0)

    def test_bulk_clamps_repetitions(self):
        pkg_full = oidrage.build_bulk_oid_package(self.tree, 0, 50)
        pkg_huge = oidrage.build_bulk_oid_package(self.tree, 0, 9999)
        self.assertEqual(pkg_full, pkg_huge)


if __name__ == '__main__':
    unittest.main()
