import unittest

from opendbc.car.can_definitions import CanData
from opendbc.car.disable_ecu import disable_ecu
from opendbc.car.hyundai import adas_uds_probe
from opendbc.car.hyundai.adas_uds_probe import probe_adas_ecu
from opendbc.car.uds import get_negative_response_description


def _encode_single_frame(payload: bytes) -> bytes:
  return (bytes([len(payload)]) + payload).ljust(8, b'\x00')


def _decode_single_frame(payload: bytes) -> bytes:
  length = payload[0] & 0x0F
  return payload[1:1 + length]


class FakeEcu:
  def __init__(self, responses: dict[bytes, bytes | None] | None = None, request_addr: int = 0x730,
               response_addr: int = 0x738, bus: int = 1):
    self.request_addr = request_addr
    self.response_addr = response_addr
    self.bus = bus
    self.responses = responses or {}
    self.pending: list[CanData] = []
    self.sent: list[CanData] = []
    self.scc_enabled = True

  def can_send(self, msgs: list[CanData]) -> None:
    for msg in msgs:
      self.sent.append(msg)
      if msg.address != self.request_addr:
        continue

      request = _decode_single_frame(msg.dat)
      response = self.responses.get(request)
      if callable(response):
        response = response(self, request)
      if response is not None:
        self.pending.append(CanData(self.response_addr, _encode_single_frame(response), self.bus))

  def can_recv(self, wait_for_one: bool = False) -> list[list[CanData]]:
    msgs = list(self.pending)
    self.pending.clear()
    if self.scc_enabled:
      msgs.append(CanData(0x1A0, b'\x00' * 8, self.bus))

    return [msgs] if msgs else []


class TestDisableEcu(unittest.TestCase):
  def test_negative_response_is_detected(self):
    ecu = FakeEcu({
      b'\x10\x03': b'\x50\x03',
      b'\x28\x83\x01': b'\x7f\x28\x22',
    })

    with self.assertLogs('carlog', level='ERROR') as logs:
      result = disable_ecu(ecu.can_recv, ecu.can_send, bus=1, addr=0x730, verify_addr=0x1A0, verify_timeout=0.01)

    self.assertFalse(result)
    self.assertTrue(any('conditions not correct' in line for line in logs.output))

  def test_success_requires_target_to_stop_transmitting(self):
    def accept(ecu: FakeEcu, _request: bytes):
      ecu.scc_enabled = False
      return None

    ecu = FakeEcu({
      b'\x10\x03': b'\x50\x03',
      b'\x28\x83\x01': accept,
    })

    result = disable_ecu(ecu.can_recv, ecu.can_send, bus=1, addr=0x730, verify_addr=0x1A0, verify_timeout=0.01)

    self.assertTrue(result)
    self.assertFalse(ecu.scc_enabled)

  def test_suppressed_response_does_not_report_success_when_still_transmitting(self):
    ecu = FakeEcu({
      b'\x10\x03': b'\x50\x03',
    })

    result = disable_ecu(ecu.can_recv, ecu.can_send, bus=1, addr=0x730, verify_addr=0x1A0, verify_timeout=0.01)

    self.assertFalse(result)
    self.assertTrue(ecu.scc_enabled)


class TestAdasUdsProbe(unittest.TestCase):
  def setUp(self):
    self._sessions = adas_uds_probe.DIAGNOSTIC_SESSIONS
    self._silence_timeout = adas_uds_probe.SILENCE_TIMEOUT
    self._restore_timeout = adas_uds_probe.RESTORE_TIMEOUT
    self._response_timeout = adas_uds_probe.RESPONSE_TIMEOUT
    self._settle_time = adas_uds_probe.SETTLE_TIME
    adas_uds_probe.DIAGNOSTIC_SESSIONS = (('extended', adas_uds_probe.EXT_DIAG, adas_uds_probe.COMMUNICATION_CONTROL_VARIANTS),)
    adas_uds_probe.SILENCE_TIMEOUT = 0.01
    adas_uds_probe.RESTORE_TIMEOUT = 0.01
    adas_uds_probe.RESPONSE_TIMEOUT = 0.01
    adas_uds_probe.SETTLE_TIME = 0.0

  def tearDown(self):
    adas_uds_probe.DIAGNOSTIC_SESSIONS = self._sessions
    adas_uds_probe.SILENCE_TIMEOUT = self._silence_timeout
    adas_uds_probe.RESTORE_TIMEOUT = self._restore_timeout
    adas_uds_probe.RESPONSE_TIMEOUT = self._response_timeout
    adas_uds_probe.SETTLE_TIME = self._settle_time

  def test_probe_accepts_tx_only_and_restores(self):
    def accept_tx_only(ecu: FakeEcu, _request: bytes):
      ecu.scc_enabled = False
      return None

    def restore(ecu: FakeEcu, _request: bytes):
      ecu.scc_enabled = True
      return b'\x68\x00\x01'

    ecu = FakeEcu({
      b'\x10\x03': b'\x50\x03',
      b'\x10\x01': b'\x50\x01',
      b'\x28\x81\x01': accept_tx_only,
      b'\x28\x00\x01': restore,
    })

    accepted = probe_adas_ecu(ecu.can_recv, ecu.can_send, bus=1)

    self.assertEqual(accepted, 'extended_tx_only_suppress_normal')
    self.assertTrue(ecu.scc_enabled)
    self.assertIn(CanData(0x730, _encode_single_frame(b'\x28\x00\x01'), 1), ecu.sent)

  def test_probe_accepts_message_type_variant(self):
    def accept_full_nm(ecu: FakeEcu, _request: bytes):
      ecu.scc_enabled = False
      return b'\x68\x83\x03'

    def restore(ecu: FakeEcu, _request: bytes):
      ecu.scc_enabled = True
      return b'\x68\x00\x01'

    ecu = FakeEcu({
      b'\x10\x03': b'\x50\x03',
      b'\x10\x01': b'\x50\x01',
      b'\x28\x83\x03': accept_full_nm,
      b'\x28\x00\x01': restore,
    })

    accepted = probe_adas_ecu(ecu.can_recv, ecu.can_send, bus=1)

    self.assertEqual(accepted, 'extended_full_suppress_normal_nm')
    self.assertTrue(ecu.scc_enabled)

  def test_probe_uses_safety_session_when_extended_session_is_unavailable(self):
    adas_uds_probe.DIAGNOSTIC_SESSIONS = (('safety', adas_uds_probe.SAFETY_DIAG, adas_uds_probe.SAFETY_VARIANTS),)

    def accept_tx_only(ecu: FakeEcu, _request: bytes):
      ecu.scc_enabled = False
      return None

    def restore(ecu: FakeEcu, _request: bytes):
      ecu.scc_enabled = True
      return b'\x68\x00\x01'

    ecu = FakeEcu({
      b'\x10\x04': b'\x50\x04',
      b'\x10\x01': b'\x50\x01',
      b'\x28\x81\x01': accept_tx_only,
      b'\x28\x00\x01': restore,
    })

    accepted = probe_adas_ecu(ecu.can_recv, ecu.can_send, bus=1)

    self.assertEqual(accepted, 'safety_tx_only_suppress_normal')
    self.assertTrue(ecu.scc_enabled)

  def test_probe_returns_none_when_all_variants_fail(self):
    ecu = FakeEcu({
      b'\x10\x03': b'\x50\x03',
      b'\x10\x01': b'\x50\x01',
      b'\x27\x01': b'\x7f\x27\x11',
    })

    accepted = probe_adas_ecu(ecu.can_recv, ecu.can_send, bus=1)

    self.assertIsNone(accepted)
    self.assertTrue(ecu.scc_enabled)
    self.assertIn(CanData(0x730, _encode_single_frame(b'\x27\x01'), 1), ecu.sent)


class TestNegativeResponseDescription(unittest.TestCase):
  def test_known_and_unknown_codes(self):
    self.assertEqual(get_negative_response_description(0x22), 'conditions not correct')
    self.assertEqual(get_negative_response_description(0xFE), 'unknown (0xfe)')
