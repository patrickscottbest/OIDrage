import os
import socket
import subprocess
import sys
import time
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from snmp_test_helpers import build_snmp_pdu, oid_sysdescr_hex

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixtures', 'tiny_mimic.txt')
OIDRAGE = os.path.join(ROOT, 'OIDrage.py')


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class TestSmokeUDP(unittest.TestCase):
    def setUp(self):
        self.port = free_udp_port()
        self.community = 'testcomm'
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        self.proc = subprocess.Popen(
            [
                sys.executable,
                OIDRAGE,
                '-f', FIXTURE,
                '-i', '127.0.0.1',
                '-p', str(self.port),
                '-c', self.community,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        # Wait until the server reports it is listening (UDP sendto is not proof).
        deadline = time.time() + 8
        output_lines = []
        while time.time() < deadline:
            if self.proc.poll() is not None:
                rest = self.proc.stdout.read() or ''
                self.fail(
                    'OIDrage exited early:\n' + ''.join(output_lines) + rest
                )
            line = self.proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            output_lines.append(line)
            if 'Listening' in line:
                break
        else:
            self.fail(
                'OIDrage did not become ready in time:\n' + ''.join(output_lines)
            )

    def tearDown(self):
        if not self.proc:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
        if self.proc.stdout:
            self.proc.stdout.close()

    def _exchange(self, packet, timeout=2.0):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, ('127.0.0.1', self.port))
            return sock.recvfrom(65535)[0]

    def test_get_sysdescr_roundtrip(self):
        req_id = b'\x0a\x0b\x0c\x0d'
        packet = build_snmp_pdu(
            self.community, oid_sysdescr_hex(), request_id=req_id, version=1, pdu_type=0xA0
        )
        response = self._exchange(packet)
        self.assertEqual(response[0], 0x30)
        self.assertIn(0xA2, response)  # get-response PDU
        self.assertIn(req_id, response)
        self.assertIn(b'OIDrage test device', response)

    def test_wrong_community_no_response(self):
        packet = build_snmp_pdu(
            'wrong', oid_sysdescr_hex(), request_id=b'\x01\x02\x03\x04', pdu_type=0xA0
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.75)
            sock.sendto(packet, ('127.0.0.1', self.port))
            with self.assertRaises(socket.timeout):
                sock.recvfrom(65535)

    def test_getbulk_large_repetitions_survives(self):
        packet = build_snmp_pdu(
            self.community,
            oid_sysdescr_hex(),
            request_id=b'\x55\x66\x77\x88',
            pdu_type=0xA5,
            max_repetitions=255,
        )
        response = self._exchange(packet)
        self.assertEqual(response[0], 0x30)
        self.assertIn(0xA2, response)
        # response should stay modest (bulk capped)
        self.assertLess(len(response), 2000)


class TestStartupPolicySmoke(unittest.TestCase):
    def test_refuse_non_loopback_without_community(self):
        port = free_udp_port()
        proc = subprocess.run(
            [
                sys.executable,
                OIDRAGE,
                '-f', FIXTURE,
                '-i', '0.0.0.0',
                '-p', str(port),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertNotEqual(proc.returncode, 0)
        combined = (proc.stdout or '') + (proc.stderr or '')
        self.assertIn('community', combined.lower())


if __name__ == '__main__':
    unittest.main()
