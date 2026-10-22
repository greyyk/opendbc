import os
import time

from opendbc.car import uds
from opendbc.car.carlog import carlog
from opendbc.car.disable_ecu import can_addr_seen, drain_can, send_uds_request

ADAS_ECU_ADDR = 0x730
ADAS_SCC_MSG = 0x1A0

TESTER_PRESENT = b'\x3e\x80'
EXT_DIAG = b'\x10\x03'
SAFETY_DIAG = b'\x10\x04'
DEFAULT_SESSION = b'\x10\x01'
RESTORE_COMM_CONTROL = b'\x28\x00\x01'

RESPONSE_TIMEOUT = 0.3
SILENCE_TIMEOUT = 0.4
RESTORE_TIMEOUT = 1.0
SETTLE_TIME = 0.05

# Control type is the low 7 bits, bit 7 suppresses the positive response.
# Message type is 1 = normal, 2 = network management, 3 = both.
# The plain full disable (0x28 83 01) is already tried by disable_ecu. Keep the probe short since it
# runs inside CarInterface.init and blocks the card process.
COMMUNICATION_CONTROL_VARIANTS = (
  ('tx_only_suppress_normal', b'\x28\x81\x01'),
  ('full_suppress_normal_nm', b'\x28\x83\x03'),
  ('tx_only_suppress_normal_nm', b'\x28\x81\x03'),
  ('full_normal', b'\x28\x03\x01'),
)

DELAYED_RETRY_VARIANTS = (
  ('tx_only_suppress_normal_retry', b'\x28\x81\x01'),
)

SAFETY_VARIANTS = (
  ('tx_only_suppress_normal', b'\x28\x81\x01'),
  ('full_suppress_normal_nm', b'\x28\x83\x03'),
)

DIAGNOSTIC_SESSIONS = (
  ('extended', EXT_DIAG, COMMUNICATION_CONTROL_VARIANTS),
  ('safety', SAFETY_DIAG, SAFETY_VARIANTS),
)


def _response_description(response: bytes | None) -> str:
  if response is None:
    return 'no response'
  if len(response) > 0 and response[0] == 0x7F:
    nrc = response[2] if len(response) > 2 else -1
    return f'negative 0x{response.hex()} ({uds.get_negative_response_description(nrc)})'
  return f'0x{response.hex()}'


def _is_positive(response: bytes | None, service: int) -> bool:
  return response is not None and len(response) > 0 and response[0] == service + 0x40


def _send(can_recv, can_send, bus: int, addr: int, request: bytes, label: str, timeout: float = RESPONSE_TIMEOUT) -> bytes | None:
  response = send_uds_request(can_recv, can_send, bus, addr, None, request, timeout)
  carlog.warning(f'adas uds probe {label}: tx=0x{request.hex()} rx={_response_description(response)}')
  return response


def _restore(can_recv, can_send, bus: int, addr: int, verify_addr: int) -> bool:
  carlog.warning('adas uds probe restore: re-enabling rx/tx')
  response = None
  for attempt in range(3):
    response = _send(can_recv, can_send, bus, addr, RESTORE_COMM_CONTROL, f'restore_attempt_{attempt + 1}', timeout=RESPONSE_TIMEOUT)
    if _is_positive(response, uds.SERVICE_TYPE.COMMUNICATION_CONTROL):
      break
    time.sleep(0.2)

  drain_can(can_recv)
  returned = can_addr_seen(can_recv, bus, verify_addr, RESTORE_TIMEOUT)
  carlog.warning(f'adas uds probe restore: {hex(verify_addr)} transmitting after restore: {returned}')

  # Always leave the ECU in the default session, even if it already resumed transmitting.
  _send(can_recv, can_send, bus, addr, DEFAULT_SESSION, 'restore_default_session', timeout=RESPONSE_TIMEOUT)
  drain_can(can_recv)
  returned = can_addr_seen(can_recv, bus, verify_addr, RESTORE_TIMEOUT)
  carlog.warning(f'adas uds probe restore: {hex(verify_addr)} transmitting after default session: {returned}')

  if not returned:
    carlog.error('adas uds probe restore: ADAS ECU did not resume transmitting; a power cycle may be required')

  return returned


def _enter_session(can_recv, can_send, bus: int, addr: int, label: str, request: bytes) -> bool:
  for attempt in range(2):
    response = _send(can_recv, can_send, bus, addr, request, f'{label}_session_attempt_{attempt + 1}')
    if response is not None and response.startswith(bytes([uds.SERVICE_TYPE.DIAGNOSTIC_SESSION_CONTROL + 0x40, request[1]])):
      return True
    time.sleep(0.3)
  return False


def _run_variants(can_recv, can_send, bus: int, addr: int, verify_addr: int, variants,
                  session_request: bytes | None, label: str) -> tuple[str | None, bool]:
  accepted = None
  needs_restore = False

  for name, request in variants:
    _send(can_recv, can_send, bus, addr, TESTER_PRESENT, f'{label}_tester_present', timeout=0.1)
    response = _send(can_recv, can_send, bus, addr, request, f'{label}_{name}')
    positive = _is_positive(response, uds.SERVICE_TYPE.COMMUNICATION_CONTROL)
    if positive:
      needs_restore = True

    time.sleep(SETTLE_TIME)
    drain_can(can_recv)
    silenced = not can_addr_seen(can_recv, bus, verify_addr, SILENCE_TIMEOUT)
    carlog.warning(f'adas uds probe {label}_{name}: positive={positive} silenced={silenced}')

    if silenced:
      accepted = f'{label}_{name}'
      needs_restore = True
      break

    # A positive response that did not silence the ECU may have changed its receive state.
    # Restore before trying the next variant so the ECU can still receive our requests.
    if positive:
      restored = _restore(can_recv, can_send, bus, addr, verify_addr)
      needs_restore = not restored
      if not restored:
        carlog.error(f'adas uds probe {label}: aborting remaining variants because the ECU did not restore')
        break
      if session_request is not None:
        _enter_session(can_recv, can_send, bus, addr, f'{label}_after_restore', session_request)

  return accepted, needs_restore


def probe_adas_ecu(can_recv, can_send, bus: int, addr: int = ADAS_ECU_ADDR,
                   verify_addr: int = ADAS_SCC_MSG, restore: bool = True) -> str | None:
  """Probe the ADAS ECU with communication control variants and restore it afterwards.

  This is intentionally diagnostic: it does not leave the ECU disabled. Results are logged through carlog,
  which is uploaded in the route's rlog as logMessage events.
  """
  if os.environ.get('REPLAY'):
    carlog.warning('adas uds probe: skipped in replay')
    return None

  carlog.warning(f'adas uds probe start: addr={hex(addr)} bus={bus} verify={hex(verify_addr)}')
  drain_can(can_recv)
  present_before = can_addr_seen(can_recv, bus, verify_addr, 0.5)
  carlog.warning(f'adas uds probe precheck: {hex(verify_addr)} present: {present_before}')

  accepted = None
  needs_restore = False
  active_session = None
  session_name = None

  try:
    for label, session_request, variants in DIAGNOSTIC_SESSIONS:
      if not _enter_session(can_recv, can_send, bus, addr, label, session_request):
        carlog.warning(f'adas uds probe {label} session unavailable')
        continue

      active_session = session_request
      session_name = label
      drain_can(can_recv)
      session_present = can_addr_seen(can_recv, bus, verify_addr, 0.5)
      carlog.warning(f'adas uds probe {label} session: {hex(verify_addr)} present: {session_present}')

      if not session_present:
        accepted = f'{label}_session_only'
        break

      accepted, needs_restore = _run_variants(can_recv, can_send, bus, addr, verify_addr, variants, session_request, label)
      if accepted is not None:
        break

      if needs_restore:
        restored = _restore(can_recv, can_send, bus, addr, verify_addr)
        needs_restore = not restored
        if not restored:
          break

    if accepted is None:
      carlog.warning(f'adas uds probe: no immediate variant worked, retrying after a delay in {session_name or "default"} session')
      time.sleep(1.0)
      if active_session is not None:
        _enter_session(can_recv, can_send, bus, addr, 'retry', active_session)
      _send(can_recv, can_send, bus, addr, TESTER_PRESENT, 'retry_tester_present', timeout=0.1)
      accepted, needs_restore = _run_variants(can_recv, can_send, bus, addr, verify_addr,
                                              DELAYED_RETRY_VARIANTS, active_session, 'retry')

    if accepted is None:
      # This only reads whether a seed is required; it does not attempt a key exchange.
      _send(can_recv, can_send, bus, addr, b'\x27\x01', 'security_access_seed')
  except Exception:
    carlog.exception('adas uds probe exception')
  finally:
    if needs_restore and restore:
      _restore(can_recv, can_send, bus, addr, verify_addr)
    elif not needs_restore:
      # The probe may have entered an extended or safety diagnostic session without changing communication.
      # Always return the ECU to the default session before handing control back to the rest of openpilot.
      _send(can_recv, can_send, bus, addr, DEFAULT_SESSION, 'probe_exit_default_session')

  carlog.warning(f'adas uds probe complete: accepted={accepted} present_before={present_before} session={session_name}')
  return accepted
