"""
Canon GP-E2 GPS receiver log reader via USB/PTP.

Reverse-engineered from a USBPcap trace of the official Canon GPS Log Tool.
The device speaks PTP over USB with several Canon-proprietary operation codes.
"""

import os
import struct
import sys
import datetime
from dataclasses import dataclass
from typing import Optional

try:
    import usb.core
    import usb.util
except ImportError:
    sys.exit("pyusb not found — install with: pip install pyusb")

# ── USB device identifiers ──────────────────────────────────────────────────
CANON_VID = 0x04A9
GPE2_PID  = 0x3251  # Canon GP-E2

# ── USB endpoints ────────
EP_BULK_OUT = 0x02
EP_BULK_IN  = 0x81
EP_INT_IN   = 0x83  # event endpoint (unused for basic operation)
USB_TIMEOUT_MS = 5000

# ── PTP container types ──────────────────────────────────────────────────────
PTP_CMD  = 0x0001
PTP_DATA = 0x0002
PTP_RESP = 0x0003

# ── PTP operation/response codes ─────────────────────────────────────────────
PTP_OP_GetDeviceInfo    = 0x1001
PTP_OP_OpenSession      = 0x1002
PTP_OP_CloseSession     = 0x1003
PTP_RC_OK               = 0x2001

# ── Canon GP-E2 proprietary operation codes (from GetDeviceInfo response) ────
CANON_OP_GetGPSLogList  = 0x9108  # returns list of Canon device-property handles
CANON_OP_InitGPSMode    = 0x9114  # call with param=1 to enable GPS log access
CANON_OP_GetGPSStatus   = 0x91A7  # GPS status query; returns OK + param=0
CANON_OP_GetGPSLogInfo  = 0x91A3  # get file list (name, handle, size, timestamps)
CANON_OP_GetGPSLogData  = 0x91A4  # get binary GPS log data; params=[handle, offset, chunk]

# Canon device property used to negotiate the transfer chunk size
CANON_PROP_TransferSize = 0xD16E  # value observed in trace: 0x2000 = 8192 bytes
CANON_PROP_LogInterval  = 0xD14F  # log interval in seconds (enum: 1,5,10,15,30,60,120,300)

# ── PTP standard property operation codes ────────────────────────────────────
PTP_OP_GetDevicePropDesc  = 0x1014
PTP_OP_GetDevicePropValue = 0x1015
PTP_OP_SetDevicePropValue = 0x1016

# ── PTP scalar data-type codes → (struct_fmt, byte_size) ─────────────────────
_PTP_DTC_FMT: dict[int, tuple[str, int]] = {
    0x0002: ("<B", 1),   # UINT8
    0x0003: ("<b", 1),   # INT8
    0x0004: ("<H", 2),   # UINT16
    0x0005: ("<h", 2),   # INT16
    0x0006: ("<I", 4),   # UINT32
    0x0007: ("<i", 4),   # INT32
    0x0008: ("<Q", 8),   # UINT64
    0x0009: ("<q", 8),   # INT64
}

# ── GPS record format (32 bytes, sync 0x5A...0xA5) ───────────────────────────
GPS_RECORD_SIZE = 32
GPS_SYNC_START  = 0x5A
GPS_SYNC_END    = 0xA5


@dataclass
class GPSRecord:
    timestamp: datetime.datetime
    lat: float   # decimal degrees, positive=N
    lon: float   # decimal degrees, positive=E
    alt_m: int   # altitude in metres (LE int16 from bytes 19-20)
    satellites: int
    hdop: float  # horizontal DOP = rec[22] + rec[23]/10  (confirmed vs NMEA GPGGA)
    raw: bytes = b""  # full 32-byte record for debugging

    def to_gpx_trkpt(self) -> str:
        ts = self.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        return (
            f'      <trkpt lat="{self.lat:.7f}" lon="{self.lon:.7f}">\n'
            f'        <ele>{self.alt_m}</ele>\n'
            f'        <time>{ts}</time>\n'
            f'        <sat>{self.satellites}</sat>\n'
            f'        <hdop>{self.hdop:.1f}</hdop>\n'
            f'      </trkpt>'
        )

    def debug_str(self) -> str:
        """One-line summary + annotated hex dump of the raw 32-byte record."""
        summary = (f"{self.timestamp.isoformat()}  "
                   f"lat={self.lat:>11.7f}  lon={self.lon:>12.7f}  "
                   f"alt={self.alt_m:>5}m  sats={self.satellites}  hdop={self.hdop:.1f}")
        if not self.raw:
            return summary
        b = self.raw
        hex_parts = [
            f"[{b[0]:02x}]",
            f"[{b[1]:02x}]",
            " ".join(f"{x:02x}" for x in b[2:8]),
            f"[{b[8]:02x} {b[9]:02x}]",
            " ".join(f"{x:02x}" for x in b[10:14]),
            " ".join(f"{x:02x}" for x in b[14:19]),
            " ".join(f"{x:02x}" for x in b[19:24]),
            " ".join(f"{x:02x}" for x in b[24:28]),
            " ".join(f"{x:02x}" for x in b[28:31]),
            f"[{b[31]:02x}]",
        ]
        return (summary + "\n"
                + "  hex: " + "  ".join(hex_parts) + "\n"
                + f"  b[8]={b[8]:#04x} b[9]={b[9]:#04x}  "
                  f"hdop={b[22]}.{b[23]}  b[24:28]={b[24:28].hex()}")


@dataclass
class GPSLogInfo:
    handle: int
    filename: str
    size: int
    start_time: Optional[datetime.datetime]
    end_time: Optional[datetime.datetime]


@dataclass
class DevicePropDesc:
    prop_code: int
    data_type: int
    writable: bool
    factory_default: int
    current_value: int
    form_flag: int           # 0=none, 1=range, 2=enum
    enum_values: list[int]   # populated when form_flag==2
    range_min: Optional[int]
    range_max: Optional[int]
    range_step: Optional[int]


# ── PTP framing helpers ───────────────────────────────────────────────────────

def build_command(op_code: int, txn_id: int, params: list[int] = ()) -> bytes:
    """Build a PTP command container."""
    n_params = len(params)
    length = 12 + n_params * 4
    hdr = struct.pack("<IHHI", length, PTP_CMD, op_code, txn_id)
    return hdr + struct.pack(f"<{n_params}I", *params)


def build_data(op_code: int, txn_id: int, payload: bytes) -> bytes:
    """Build a PTP data container."""
    length = 12 + len(payload)
    hdr = struct.pack("<IHHI", length, PTP_DATA, op_code, txn_id)
    return hdr + payload


def parse_response(data: bytes) -> tuple[int, list[int]]:
    """Parse a PTP response container. Returns (response_code, params)."""
    if len(data) < 12:
        raise RuntimeError(f"Response too short ({len(data)} bytes)")
    length, ctype, code, txn_id = struct.unpack_from("<IHHI", data, 0)
    if ctype != PTP_RESP:
        raise RuntimeError(f"Expected RESPONSE container (type 3), got type {ctype}")
    n_params = (length - 12) // 4
    params = list(struct.unpack_from(f"<{n_params}I", data, 12))
    return code, params


def parse_data_container(data: bytes) -> tuple[int, bytes]:
    """Parse a PTP data container. Returns (op_code, payload)."""
    if len(data) < 12:
        raise RuntimeError(f"Data container too short ({len(data)} bytes)")
    length, ctype, code, txn_id = struct.unpack_from("<IHHI", data, 0)
    if ctype != PTP_DATA:
        raise RuntimeError(f"Expected DATA container (type 2), got type {ctype}")
    return code, data[12:length]


def _prop_value(data: bytes, off: int, data_type: int) -> tuple[int, int]:
    """Read one scalar PTP property value. Returns (value, next_offset)."""
    fmt, size = _PTP_DTC_FMT.get(data_type, ("<I", 4))
    return struct.unpack_from(fmt, data, off)[0], off + size


def parse_prop_desc(data: bytes) -> DevicePropDesc:
    """Parse a PTP GetDevicePropDesc payload into a DevicePropDesc."""
    off = 0
    prop_code = struct.unpack_from("<H", data, off)[0]
    off += 2
    data_type = struct.unpack_from("<H", data, off)[0]
    off += 2
    writable = data[off] == 0x01
    off += 1
    factory_default, off = _prop_value(data, off, data_type)
    current_value, off   = _prop_value(data, off, data_type)
    form_flag = data[off]
    off += 1

    enum_values: list[int] = []
    range_min = range_max = range_step = None
    if form_flag == 0x01:  # Range form
        range_min,  off = _prop_value(data, off, data_type)
        range_max,  off = _prop_value(data, off, data_type)
        range_step, off = _prop_value(data, off, data_type)
    elif form_flag == 0x02:  # Enumeration form
        count = struct.unpack_from("<H", data, off)[0]
        off += 2
        for _ in range(count):
            v, off = _prop_value(data, off, data_type)
            enum_values.append(v)

    return DevicePropDesc(
        prop_code=prop_code, data_type=data_type, writable=writable,
        factory_default=factory_default, current_value=current_value,
        form_flag=form_flag, enum_values=enum_values,
        range_min=range_min, range_max=range_max, range_step=range_step,
    )


# ── Low-level USB I/O ─────────────────────────────────────────────────────────

class PTPDevice:
    def __init__(self, dev: "usb.core.Device"):
        self.dev = dev
        self._txn_id = 0

    def _next_txn(self) -> int:
        self._txn_id += 1
        return self._txn_id

    def _write(self, data: bytes):
        n = self.dev.write(EP_BULK_OUT, data, USB_TIMEOUT_MS)
        if n != len(data):
            raise RuntimeError(f"Short write: sent {n}/{len(data)} bytes")

    def _read(self, max_len: int = 65536) -> bytes:
        """Read one bulk IN transfer (may be a fragment)."""
        return bytes(self.dev.read(EP_BULK_IN, max_len, USB_TIMEOUT_MS))

    def _read_all(self) -> bytes:
        """Read until we have a complete PTP container (handles multi-packet)."""
        buf = bytearray()
        while True:
            chunk = self._read(65536)
            buf += chunk
            if len(buf) < 4:
                continue
            expected = struct.unpack_from("<I", buf, 0)[0]
            if len(buf) >= expected:
                return bytes(buf[:expected])
            # still more to read

    def send_command(self, op_code: int, params: list[int] = ()) -> int:
        """Send a command container, return the new transaction ID."""
        txn = self._next_txn()
        self._write(build_command(op_code, txn, params))
        return txn

    def send_data(self, op_code: int, txn: int, payload: bytes):
        """Send a data container for an in-progress transaction."""
        self._write(build_data(op_code, txn, payload))

    def _read_container(self) -> tuple[int, bytes]:
        """Read any PTP container. Returns (container_type, raw_bytes)."""
        raw = self._read_all()
        if len(raw) < 6:
            raise RuntimeError(f"Container too short: {len(raw)} bytes")
        ctype = struct.unpack_from("<H", raw, 4)[0]
        return ctype, raw

    def read_response(self) -> tuple[int, list[int]]:
        """Read a PTP response container."""
        raw = self._read_all()
        return parse_response(raw)

    def do_command(self, op_code: int, params: list[int] = ()) -> tuple[int, list[int]]:
        """Send command, read response. Returns (resp_code, resp_params)."""
        self.send_command(op_code, params)
        return self.read_response()

    def do_command_data_in(self, op_code: int,
                           params: list[int] = ()) -> tuple[Optional[bytes], int, list[int]]:
        """Send command; read optional DATA then RESPONSE.
        Returns (payload_or_None, resp_code, resp_params).
        Handles devices that skip the data phase and send only a RESPONSE."""
        self.send_command(op_code, params)
        ctype, raw = self._read_container()
        if ctype == PTP_DATA:
            _, payload = parse_data_container(raw)
            resp_code, resp_params = self.read_response()
            return payload, resp_code, resp_params
        elif ctype == PTP_RESP:
            resp_code, resp_params = parse_response(raw)
            return None, resp_code, resp_params
        else:
            raise RuntimeError(f"Unexpected container type {ctype:#06x}")

    def get_device_prop_desc(self, prop_code: int) -> DevicePropDesc:
        data, code, _ = self.do_command_data_in(PTP_OP_GetDevicePropDesc, [prop_code])
        if code != PTP_RC_OK or data is None:
            raise RuntimeError(f"GetDevicePropDesc(0x{prop_code:04X}) failed: 0x{code:04X}")
        return parse_prop_desc(data)

    def set_device_prop_value(self, prop_code: int, value: int, data_type: int = 0x0006):
        fmt, _ = _PTP_DTC_FMT.get(data_type, ("<I", 4))
        payload = struct.pack(fmt, value)
        txn = self.send_command(PTP_OP_SetDevicePropValue, [prop_code])
        self.send_data(PTP_OP_SetDevicePropValue, txn, payload)
        code, _ = self.read_response()
        if code != PTP_RC_OK:
            raise RuntimeError(
                f"SetDevicePropValue(0x{prop_code:04X}={value}) failed: 0x{code:04X}")

    def open_session(self, session_id: int = 1):
        code, _ = self.do_command(PTP_OP_OpenSession, [session_id])
        if code != PTP_RC_OK:
            raise RuntimeError(f"OpenSession failed: 0x{code:04X}")

    def close_session(self):
        self.do_command(PTP_OP_CloseSession)

    def get_device_info(self) -> bytes:
        data, code, _ = self.do_command_data_in(PTP_OP_GetDeviceInfo)
        if code != PTP_RC_OK:
            raise RuntimeError(f"GetDeviceInfo failed: 0x{code:04X}")
        return data

    def get_gps_log_list(self) -> list[int]:
        """Call Canon 0x9108. Returns list of Canon device-property codes."""
        data, code, _ = self.do_command_data_in(CANON_OP_GetGPSLogList)
        if code != PTP_RC_OK:
            raise RuntimeError(f"GetGPSLogList (0x9108) failed: 0x{code:04X}")
        # Payload: [total_len u32][unknown u32][count u32][handle × count u32][...]
        if len(data) < 12:
            return []
        count = struct.unpack_from("<I", data, 8)[0]
        handles = []
        for i in range(count):
            off = 12 + i * 4
            if off + 4 > len(data):
                break
            handles.append(struct.unpack_from("<I", data, off)[0])
        return handles

    def init_gps_mode(self):
        """Required initialisation sequence before reading GPS logs.

        Observed in trace:
          txn=5: 0x9114 param=1 → RESP OK       (enable GPS log access mode)
          txn=6: 0x91A7 no params → RESP OK + param=0  (GPS status query)
        Without this, 0x91A3 returns 0x2005 (OperationNotSupported).
        """
        code, _ = self.do_command(CANON_OP_InitGPSMode, [1])
        if code != PTP_RC_OK:
            raise RuntimeError(f"InitGPSMode (0x9114) failed: 0x{code:04X}")
        _, code, _ = self.do_command_data_in(CANON_OP_GetGPSStatus)
        if code != PTP_RC_OK:
            raise RuntimeError(f"GetGPSStatus (0x91A7) failed: 0x{code:04X}")

    def get_gps_transfer_size(self) -> int:
        """Read Canon device property 0xD16E to get negotiated transfer chunk size.

        The Canon tool reads this value (observed: 0x2000 = 8192) and passes it
        as the third parameter to 0x91A4. Uses op 0x1015 which the device treats
        as a GetDevicePropValue-style read for this property.
        """
        data, code, _ = self.do_command_data_in(PTP_OP_GetDevicePropValue, [CANON_PROP_TransferSize])
        if code != PTP_RC_OK or not data:
            return 0x2000  # safe fallback matching observed value
        return struct.unpack_from("<I", data, 0)[0]

    def get_gps_log_infos(self) -> list[GPSLogInfo]:
        """Call Canon 0x91A3 with no params. Returns list of GPS log file metadata.

        Payload layout (per entry, 44 bytes each, preceded by u32 count):
          [handle u32][filename 16 bytes ASCII null-padded][size u32]
          [day u8][month u8][year-2000 u8][pad u8]
          [hour u8][min u8][sec u8][pad u8]
          [4 zeros][hour u8][min u8][sec u8][pad u8][4 zeros]
        """
        data, code, _ = self.do_command_data_in(CANON_OP_GetGPSLogInfo)
        if code != PTP_RC_OK or data is None:
            raise RuntimeError(f"GetGPSLogInfo (0x91A3) failed: 0x{code:04X}"
                                + (" (no data returned)" if data is None else ""))

        if len(data) < 4:
            return []
        count = struct.unpack_from("<I", data, 0)[0]
        infos = []
        ENTRY_SIZE = 44
        for i in range(count):
            base = 4 + i * ENTRY_SIZE
            if base + ENTRY_SIZE > len(data):
                break
            e = data[base:base + ENTRY_SIZE]

            file_handle = struct.unpack_from("<I", e, 0)[0]
            filename    = e[4:20].split(b"\x00")[0].decode("ascii", errors="replace")
            file_size   = struct.unpack_from("<I", e, 20)[0]

            start_time = end_time = None
            try:
                day, month, year_off, _ = e[24:28]
                hour, minute, sec, _    = e[28:32]
                start_time = datetime.datetime(2000 + year_off, month, day, hour, minute, sec)
                hour2, minute2, sec2, _ = e[36:40]
                end_time = datetime.datetime(2000 + year_off, month, day, hour2, minute2, sec2)
            except (ValueError, struct.error):
                pass

            infos.append(GPSLogInfo(handle=file_handle, filename=filename,
                                    size=file_size, start_time=start_time, end_time=end_time))
        return infos

    def get_gps_log_data(self, handle: int, total_size: int,
                         chunk_size: int = 0x2000) -> bytes:
        """Download a GPS log file via Canon 0x91A4, in chunks if needed.

        params: [handle, byte_offset, chunk_size]
        Loops with increasing byte offsets until total_size bytes are received.
        """
        buf = bytearray()
        while len(buf) < total_size:
            data, code, _ = self.do_command_data_in(
                CANON_OP_GetGPSLogData, [handle, len(buf), chunk_size])
            if code != PTP_RC_OK:
                raise RuntimeError(
                    f"GetGPSLogData (0x91A4) failed: 0x{code:04X} at offset {len(buf)}")
            if not data:
                raise RuntimeError(
                    f"GetGPSLogData (0x91A4) returned no data at offset {len(buf)}")
            buf += data
            if len(data) < chunk_size:
                break  # device signalled end of file
        return bytes(buf[:total_size])


# ── PTP DeviceInfo parsing ────────────────────────────────────────────────────

MIN_FIRMWARE = (2, 0, 0)


@dataclass
class DeviceInfo:
    manufacturer: str
    model: str
    device_version: str   # raw PTP string, e.g. "4-2.0.2"
    serial_number: str
    device_properties: list[int]  # property codes from DevicePropertiesSupported


def _ptp_string(data: bytes, off: int) -> tuple[str, int]:
    """Parse a PTPString (uint8 numChars + numChars × UTF-16LE). Returns (str, next_off)."""
    n = data[off]
    if n == 0:
        return "", off + 1
    s = data[off + 1: off + 1 + n * 2].decode("utf-16-le", errors="replace").rstrip("\x00")
    return s, off + 1 + n * 2


def _ptp_array16(data: bytes, off: int) -> int:
    """Skip a PTP AUINT16 array (uint32 count + count × uint16). Returns next offset."""
    count = struct.unpack_from("<I", data, off)[0]
    return off + 4 + count * 2


def _ptp_array16_values(data: bytes, off: int) -> tuple[list[int], int]:
    """Read a PTP AUINT16 array. Returns (values, next_offset)."""
    count = struct.unpack_from("<I", data, off)[0]
    vals = list(struct.unpack_from(f"<{count}H", data, off + 4))
    return vals, off + 4 + count * 2


def parse_device_info(data: bytes) -> DeviceInfo:
    """Parse PTP GetDeviceInfo payload.

    DeviceInfo layout (PIMA 15740):
      StandardVersion(2) VendorExtID(4) VendorExtVersion(2) VendorExtDesc(str)
      FunctionalMode(2) OperationsSupported(AU16) EventsSupported(AU16)
      DevicePropertiesSupported(AU16) CaptureFormats(AU16) ImageFormats(AU16)
      Manufacturer(str) Model(str) DeviceVersion(str) SerialNumber(str)
    """
    off = 8                                          # skip StandardVersion + VendorExtID + VendorExtVersion
    _, off  = _ptp_string(data, off)                # VendorExtensionDesc
    off    += 2                                      # FunctionalMode
    off     = _ptp_array16(data, off)               # OperationsSupported
    off     = _ptp_array16(data, off)               # EventsSupported
    props, off = _ptp_array16_values(data, off)     # DevicePropertiesSupported
    off     = _ptp_array16(data, off)               # CaptureFormats
    off     = _ptp_array16(data, off)               # ImageFormats
    manufacturer,   off = _ptp_string(data, off)
    model,          off = _ptp_string(data, off)
    device_version, off = _ptp_string(data, off)
    serial_number,  _   = _ptp_string(data, off)
    return DeviceInfo(manufacturer=manufacturer, model=model,
                      device_version=device_version, serial_number=serial_number,
                      device_properties=props)


def _firmware_tuple(device_version: str) -> tuple[int, ...]:
    """Extract comparable version tuple from DeviceVersion (e.g. '4-2.0.2' → (2, 0, 2))."""
    ver_str = device_version.rsplit("-", 1)[-1]
    try:
        return tuple(int(x) for x in ver_str.split("."))
    except ValueError:
        return ()


def check_firmware(device_version: str, ignore_version: bool):
    fw = _firmware_tuple(device_version)
    if fw and fw < MIN_FIRMWARE:
        min_str = ".".join(str(x) for x in MIN_FIRMWARE)
        msg = (f"Firmware {device_version!r} is below the tested minimum {min_str}; "
               f"behavior is untested")
        if not ignore_version:
            sys.exit(f"{msg} — use --ignore-version to proceed anyway")
        print(f"WARNING: {msg}", file=sys.stderr)


# ── GPS record decoding ───────────────────────────────────────────────────────

def decode_gps_records(data: bytes) -> list[GPSRecord]:
    """Decode Canon GP-E2 binary GPS log into GPSRecord list.

    Record layout (32 bytes):
      [0]    0x5A  sync start
      [1]    record type (always 0x0E)
      [2]    day
      [3]    month
      [4]    year - 2000
      [5]    hour
      [6]    minute
      [7]    second
      [8-9]  flags (purpose unknown; NOT N/S/E/W — direction is in degree sign)
      [10]   lat degrees (signed int8: positive=N, negative=S)
      [11]   lat minutes integer
      [12-13] lat fractional minutes × 10000  (LE uint16)
      [14-15] lon degrees  (signed int16 LE: positive=E, negative=W)
      [16]   lon minutes integer
      [17-18] lon fractional minutes × 10000  (LE uint16)
      [19-20] altitude in metres  (LE int16)
      [21]   satellites used  (confirmed vs NMEA GPGGA numSV)
      [22]   HDOP integer part  (confirmed vs NMEA GPGGA HDOP)
      [23]   HDOP tenths digit  → HDOP = rec[22] + rec[23]/10
      [24-27] unknown
      [28-30] zeros
      [31]   0xA5  sync end
    """
    records = []
    for i in range(0, len(data) - GPS_RECORD_SIZE + 1, GPS_RECORD_SIZE):
        rec = data[i:i + GPS_RECORD_SIZE]
        if rec[0] != GPS_SYNC_START or rec[31] != GPS_SYNC_END:
            print(f"  WARNING: record {i//GPS_RECORD_SIZE} bad sync "
                  f"({rec[0]:#04x}/{rec[31]:#04x}), skipping", file=sys.stderr)
            continue

        day, month, year_off = rec[2], rec[3], rec[4]
        hour, minute, second = rec[5], rec[6], rec[7]

        # Latitude: signed int8 degree (neg=S) + minutes part with matching sign
        lat_deg      = struct.unpack_from("b", rec, 10)[0]  # signed int8
        lat_min_int  = rec[11]
        lat_min_frac = struct.unpack_from("<H", rec, 12)[0]
        lat_min_part = (lat_min_int + lat_min_frac / 10000.0) / 60.0
        lat = lat_deg + (lat_min_part if lat_deg >= 0 else -lat_min_part)

        # Longitude: signed int16 LE degree (neg=W) + minutes part with matching sign
        lon_deg      = struct.unpack_from("<h", rec, 14)[0]  # signed int16
        lon_min_int  = rec[16]
        lon_min_frac = struct.unpack_from("<H", rec, 17)[0]
        lon_min_part = (lon_min_int + lon_min_frac / 10000.0) / 60.0
        lon = lon_deg + (lon_min_part if lon_deg >= 0 else -lon_min_part)

        alt_m      = struct.unpack_from("<h", rec, 19)[0]
        satellites = rec[21]
        hdop       = rec[22] + rec[23] / 10.0

        try:
            ts = datetime.datetime(2000 + year_off, month, day, hour, minute, second)
        except ValueError:
            continue
        records.append(GPSRecord(timestamp=ts, lat=lat, lon=lon,
                                  alt_m=alt_m, satellites=satellites,
                                  hdop=hdop, raw=bytes(rec)))
    return records


def write_gpx(records: list[GPSRecord], path: str, track_name: str = "Canon GP-E2"):
    with open(path, "w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<gpx version="1.1" creator="canon_gps_reader"\n')
        f.write('     xmlns="http://www.topografix.com/GPX/1/1">\n')
        f.write(f'  <trk><name>{track_name}</name><trkseg>\n')
        for r in records:
            f.write(r.to_gpx_trkpt() + "\n")
        f.write('  </trkseg></trk>\n</gpx>\n')
    print(f"Wrote {len(records)} points to {path}")


def write_csv(records: list[GPSRecord], path: str, debug: bool = False):
    with open(path, "w") as f:
        header = "timestamp,lat,lon,alt_m,satellites,hdop"
        if debug:
            header += ",b08,b09,b24,b25,b26,b27,raw_hex"
        f.write(header + "\n")
        for r in records:
            line = (f"{r.timestamp.isoformat()},{r.lat:.7f},{r.lon:.7f},"
                    f"{r.alt_m},{r.satellites},{r.hdop:.1f}")
            if debug and r.raw:
                b = r.raw
                line += (f",{b[8]:#04x},{b[9]:#04x},"
                         f"{b[24]:#04x},{b[25]:#04x},{b[26]:#04x},{b[27]:#04x},"
                         f"{b.hex()}")
            f.write(line + "\n")
    print(f"Wrote {len(records)} points to {path}")


# ── PTP data-type display names ───────────────────────────────────────────────
_DTC_NAME: dict[int, str] = {
    0x0002: "UINT8",  0x0003: "INT8",
    0x0004: "UINT16", 0x0005: "INT16",
    0x0006: "UINT32", 0x0007: "INT32",
    0x0008: "UINT64", 0x0009: "INT64",
    0xFFFF: "UNDEF",  # Canon vendor-specific / unknown; values parsed as UINT32 fallback
}

def _format_prop_desc(desc: DevicePropDesc) -> str:
    """One-line summary of a DevicePropDesc for the list command."""
    type_str = _DTC_NAME.get(desc.data_type, f"0x{desc.data_type:04X}")
    rw = "rw" if desc.writable else "r-"
    if desc.form_flag == 0x02:
        form = "enum=[" + ", ".join(str(v) for v in desc.enum_values) + "]"
    elif desc.form_flag == 0x01:
        form = f"range=[{desc.range_min}..{desc.range_max} step {desc.range_step}]"
    else:
        form = ""
    parts = [f"current={desc.current_value}", f"default={desc.factory_default}", form]
    return f"{type_str:6}  {rw}  " + "  ".join(p for p in parts if p)


# ── Known configurable device properties ─────────────────────────────────────
# (prop_code, human label, unit suffix)
KNOWN_PROPS: dict[str, tuple[int, str, str]] = {
    "interval":      (CANON_PROP_LogInterval,  "Log interval",  "s"),
    "transfer_size": (CANON_PROP_TransferSize, "Transfer size", "B"),
}

# ── Main entry point ──────────────────────────────────────────────────────────

def find_device(vid: int = CANON_VID, pid: int = GPE2_PID):
    dev = usb.core.find(idVendor=vid, idProduct=pid)
    if dev is None:
        raise RuntimeError(f"Canon GP-E2 not found (VID={vid:#06x} PID={pid:#06x}). "
                           "Check USB connection and PID.")
    return dev


def claim_interface(dev):
    if dev.is_kernel_driver_active(0):
        dev.detach_kernel_driver(0)
    dev.set_configuration()
    usb.util.claim_interface(dev, 0)


def release_interface(dev):
    usb.util.release_interface(dev, 0)
    usb.util.dispose_resources(dev)


def _output_records(records: list[GPSRecord], stem: str,
                    output_format: str, output_dir: str, debug: bool):
    if output_format == "gpx":
        write_gpx(records, f"{output_dir}/{stem}.gpx", track_name=stem)
    elif output_format == "csv":
        write_csv(records, f"{output_dir}/{stem}.csv", debug=debug)


def run_config(action: str, prop_name: Optional[str] = None,
               value: Optional[int] = None, ignore_version: bool = False):
    dev = find_device()
    claim_interface(dev)
    ptp = PTPDevice(dev)

    try:
        ptp.open_session(1)

        info_data = ptp.get_device_info()
        dev_info = parse_device_info(info_data)
        print(f"Device: {dev_info.manufacturer} {dev_info.model}  "
              f"FW: {dev_info.device_version}  SN: {dev_info.serial_number}")
        check_firmware(dev_info.device_version, ignore_version)

        if action == "list":
            for cli_name, (prop_code, label, unit) in KNOWN_PROPS.items():
                desc = ptp.get_device_prop_desc(prop_code)
                print(f"{cli_name}: {desc.current_value}{unit}  "
                      f"(default: {desc.factory_default}{unit})")

        elif action == "get":
            assert prop_name is not None
            prop_code, label, unit = KNOWN_PROPS[prop_name]
            desc = ptp.get_device_prop_desc(prop_code)
            print(f"{label}: {desc.current_value}{unit}  "
                  f"(default: {desc.factory_default}{unit})")
            if desc.enum_values:
                vals = ", ".join(f"{v}{unit}" for v in sorted(desc.enum_values))
                print(f"  Allowed: {vals}")

        elif action == "set":
            assert prop_name is not None and value is not None
            prop_code, label, unit = KNOWN_PROPS[prop_name]
            desc = ptp.get_device_prop_desc(prop_code)
            if not desc.writable:
                sys.exit(f"Property {label!r} is read-only")
            if desc.enum_values and value not in desc.enum_values:
                allowed = ", ".join(str(v) for v in sorted(desc.enum_values))
                sys.exit(f"Value {value}{unit} not in allowed set: {allowed}")
            ptp.set_device_prop_value(prop_code, value, desc.data_type)
            print(f"Set {label} to {value}{unit}")

        ptp.close_session()

    finally:
        release_interface(dev)


def read_all_logs(output_format: str = "gpx", output_dir: str = ".",
                  debug: bool = False, overwrite: bool = False,
                  ignore_version: bool = False):
    dev = find_device()
    claim_interface(dev)
    ptp = PTPDevice(dev)

    try:
        ptp.open_session(1)

        info_data = ptp.get_device_info()
        dev_info = parse_device_info(info_data)
        print(f"Device: {dev_info.manufacturer} {dev_info.model}  "
              f"FW: {dev_info.device_version}  SN: {dev_info.serial_number}")
        check_firmware(dev_info.device_version, ignore_version)

        handles = ptp.get_gps_log_list()
        print(f"0x9108 returned {len(handles)} handles: {[f'0x{h:08X}' for h in handles]}")

        ptp.init_gps_mode()
        print("GPS mode initialised (0x9114 + 0x91A7)")

        chunk_size = ptp.get_gps_transfer_size()
        print(f"Transfer chunk size: {chunk_size:#x}")

        log_infos = ptp.get_gps_log_infos()
        print(f"0x91A3 returned {len(log_infos)} log file(s)")

        if not log_infos:
            print("No GPS logs found on device.")
            return

        for info in log_infos:
            print(f"\nFile: {info.filename}  ({info.size} bytes)")
            if info.start_time:
                print(f"  Start: {info.start_time}  End: {info.end_time}")

            if info.size == 0 or not info.filename:
                print("  (empty or no filename, skipping)")
                continue

            stem = info.filename.replace(".log", "").replace(".LOG", "")
            out_path = f"{output_dir}/{stem}.{output_format}"
            if not overwrite and os.path.exists(out_path):
                print(f"  WARNING: {out_path} already exists, skipping (use --overwrite to replace)",
                      file=sys.stderr)
                continue

            raw_data = ptp.get_gps_log_data(info.handle, info.size, chunk_size)
            print(f"  Downloaded {len(raw_data)} bytes")

            records = decode_gps_records(raw_data)
            print(f"  Decoded {len(records)} GPS records")

            _output_records(records, stem, output_format, output_dir, debug)

        ptp.close_session()
        print("\nDone.")

    finally:
        release_interface(dev)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Canon GP-E2 GPS reader")
    p.add_argument("--ignore-version", action="store_true",
                   help="Proceed even if firmware is below tested minimum (2.0.0)")
    sub = p.add_subparsers(dest="mode", required=True)

    # ── import ────────────────────────────────────────────────────────────────
    imp = sub.add_parser("import", help="Download GPS logs from device")
    imp.add_argument("--format", choices=["gpx", "csv"], default="gpx")
    imp.add_argument("--output-dir", default=".", help="Output directory")
    imp.add_argument("--debug", action="store_true",
                     help="Add raw hex + mystery bytes (b08, b09, b23-b27) to output")
    imp.add_argument("--overwrite", action="store_true",
                     help="Overwrite existing output files (default: warn and skip)")

    # ── config ────────────────────────────────────────────────────────────────
    cfg = sub.add_parser("config", help="Read or write device configuration")
    cfg_sub = cfg.add_subparsers(dest="action", required=True)

    cfg_sub.add_parser("list", help="List all advertised device properties")

    cfg_get = cfg_sub.add_parser("get", help="Read a named property")
    cfg_get.add_argument("property", choices=list(KNOWN_PROPS))

    cfg_set = cfg_sub.add_parser("set", help="Write a named property")
    cfg_set.add_argument("property", choices=list(KNOWN_PROPS))
    cfg_set.add_argument("value", type=int, help="Value to set")

    args = p.parse_args()

    if args.mode == "import":
        read_all_logs(output_format=args.format, output_dir=args.output_dir,
                      debug=args.debug, overwrite=args.overwrite,
                      ignore_version=args.ignore_version)
    elif args.mode == "config":
        run_config(action=args.action,
                   prop_name=getattr(args, "property", None),
                   value=getattr(args, "value", None),
                   ignore_version=args.ignore_version)
