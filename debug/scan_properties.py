#!/usr/bin/env python3
"""
Brute-force scan of PTP device properties over a given code range.

Usage:
    scan_properties.py <start_hex> <end_hex>

Examples:
    scan_properties.py d000 e000
    scan_properties.py 0x5000 0x5100
    scan_properties.py d14d d170

A dot is printed for each responding property so you can see progress.
"""

"""
Results on firmware 2.0.2:


CODE      NAME                  DETAILS
------------------------------------------------------------------------
0xD14D                        UINT32  rw  current=30  default=15  enum=[1, 5, 10, 15, 30, 60, 120, 300]
0xD14E                        UINT32  r-  current=600  default=600
0xD14F  LogInterval           UINT32  rw  current=30  default=15  enum=[1, 5, 10, 15, 30, 60, 120, 300]
0xD16C                        UNDEF   r-  current=805318912  default=855650315
0xD16D                        UINT32  r-  current=2147484451  default=2147484451
0xD16E  TransferSize          UINT32  r-  current=8192  default=8192
0xD16F                        UINT32  r-  current=8192  default=8192
0xD407                        UINT32  r-  current=1  default=1

Canon software sets the second LogInterval, first one auto-updates to the same value
"""

import sys
import os

CANON_PROP_TransferSize = 0xD16E  # value observed in trace: 0x2000 = 8192 bytes
CANON_PROP_LogInterval  = 0xD14F  # log interval in seconds (enum: 1,5,10,15,30,60,120,300)

# ── Known property codes → display name ──────────────────────────────────────
_PROP_NAMES: dict[int, str] = {
    CANON_PROP_LogInterval:  "LogInterval",
    CANON_PROP_TransferSize: "TransferSize",
}


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from canon_gps_reader import (
    find_device, claim_interface, release_interface,
    PTPDevice, parse_device_info, check_firmware,
    _format_prop_desc,
)


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} <start_hex> <end_hex>")
    try:
        start = int(sys.argv[1], 16)
        end   = int(sys.argv[2], 16)
    except ValueError:
        sys.exit("Addresses must be hex integers, e.g.  d000 e000  or  0xD000 0xE000")
    if start >= end:
        sys.exit(f"start (0x{start:04X}) must be less than end (0x{end:04X})")

    dev = find_device()
    claim_interface(dev)
    ptp = PTPDevice(dev)

    try:
        ptp.open_session(1)

        info_data = ptp.get_device_info()
        dev_info  = parse_device_info(info_data)
        print(f"Device: {dev_info.manufacturer} {dev_info.model}  "
              f"FW: {dev_info.device_version}  SN: {dev_info.serial_number}")
        check_firmware(dev_info.device_version, ignore_version=True)

        n = end - start
        print(f"\nScanning 0x{start:04X}–0x{end-1:04X} ({n} codes) …", end="", flush=True)

        found = []
        for code in range(start, end):
            try:
                found.append(ptp.get_device_prop_desc(code))
                print(".", end="", flush=True)
            except RuntimeError:
                pass

        print(f"\n\n{len(found)} properties found\n")
        print(f"{'CODE':<8}  {'NAME':<20}  DETAILS")
        print("-" * 72)
        for desc in found:
            name = _PROP_NAMES.get(desc.prop_code, "")
            print(f"0x{desc.prop_code:04X}  {name:<20}  {_format_prop_desc(desc)}")

        ptp.close_session()

    finally:
        release_interface(dev)


if __name__ == "__main__":
    main()
