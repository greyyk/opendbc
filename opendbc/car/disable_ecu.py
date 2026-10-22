import time

from opendbc.car import uds
from opendbc.car.carlog import carlog
from opendbc.car.isotp_parallel_query import IsoTpParallelQuery

EXT_DIAG_REQUEST = b'\x10\x03'
EXT_DIAG_RESPONSE = b'\x50\x03'

COM_CONT_RESPONSE = b''


def send_uds_request(can_recv, can_send, bus: int, addr: int, sub_addr: int | None, request: bytes, timeout: float = 0.2) -> bytes | None:
  """Send a single UDS request and return the raw ISO-TP response, if any.

  Unlike the UDS clients, this intentionally accepts negative responses so callers can inspect the NRC.
  """
  query = IsoTpParallelQuery(can_send, can_recv, bus, [(addr, sub_addr)], [request], [COM_CONT_RESPONSE])
  try:
    responses = query.get_data(timeout)
  except Exception:
    carlog.exception(f'UDS request exception: {hex(addr)} - 0x{request.hex()}')
    return None

  return responses.get((addr, sub_addr))


def drain_can(can_recv) -> None:
  try:
    can_recv()
  except Exception:
    carlog.exception('CAN drain exception')


def can_addr_seen(can_recv, bus: int, addr: int, timeout: float) -> bool:
  """Return True if addr was received on bus at least once within timeout seconds."""
  start_time = time.monotonic()
  while time.monotonic() - start_time < timeout:
    try:
      packets = can_recv()
    except Exception:
      carlog.exception('CAN receive exception')
      return False

    for packet in packets:
      for msg in packet:
        if msg.src == bus and msg.address == addr:
          return True

    time.sleep(0.005)

  return False


def disable_ecu(can_recv, can_send, bus=0, addr=0x7d0, sub_addr=None, com_cont_req=b'\x28\x83\x01', timeout=0.1, retry=10,
                com_cont_timeout=0.2, verify_addr=None, verify_bus=None, verify_timeout=0.5):
  """Silence an ECU by disabling sending and receiving messages using UDS 0x28.
  The ECU will stay silent as long as openpilot keeps sending Tester Present.

  This is used to disable the radar in some cars. Openpilot will emulate the radar.
  WARNING: THIS DISABLES AEB!"""
  carlog.warning(f"ecu disable {hex(addr), sub_addr} ...")

  verify_bus = bus if verify_bus is None else verify_bus
  verify_present = False
  if verify_addr is not None:
    drain_can(can_recv)
    verify_present = can_addr_seen(can_recv, verify_bus, verify_addr, verify_timeout)
    carlog.warning(f'ecu disable verification: {hex(verify_addr)} present before request: {verify_present}')

  for i in range(retry):
    try:
      query = IsoTpParallelQuery(can_send, can_recv, bus, [(addr, sub_addr)], [EXT_DIAG_REQUEST], [EXT_DIAG_RESPONSE])

      if not query.get_data(timeout):
        carlog.error(f"ecu disable retry ({i + 1}) ...")
        continue

      carlog.warning('communication control disable tx/rx ...')

      response = send_uds_request(can_recv, can_send, bus, addr, sub_addr, com_cont_req, com_cont_timeout)
      if response:
        if response[0] == 0x7F:
          nrc = response[2] if len(response) > 2 else -1
          carlog.error(f'ecu disable negative response: 0x{response.hex()} ({uds.get_negative_response_description(nrc)})')
          return False

        if response[0] != uds.SERVICE_TYPE.COMMUNICATION_CONTROL + 0x40:
          carlog.error(f'ecu disable unexpected response: 0x{response.hex()}')
          return False

        carlog.warning(f'communication control positive response: 0x{response.hex()}')

      if verify_addr is not None and verify_present:
        time.sleep(0.05)
        drain_can(can_recv)
        if can_addr_seen(can_recv, verify_bus, verify_addr, verify_timeout):
          carlog.error(f'ecu disable verification failed: {hex(verify_addr)} still transmitting')
          return False

      carlog.warning('ecu disabled')
      return True

    except Exception:
      carlog.exception("ecu disable exception")

    carlog.error(f"ecu disable retry ({i + 1}) ...")

  carlog.error("ecu disable failed")
  return False
