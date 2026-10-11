"""Optional live packet summary for SecureTransfer LAN demos.

Requires Npcap and PyShark. Application-level alerts still work without
capture via GET /security/dashboard.
"""

from __future__ import annotations

import argparse
import json
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel Monitor (PyShark)")
    parser.add_argument("--interface", default="\\Device\\NPF_Loopback")
    parser.add_argument("--packet-count", type=int, default=20)
    args = parser.parse_args()

    try:
        import pyshark
    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": "PyShark is not available on this machine.",
                    "detail": str(exc),
                    "fallback": "Use GET /security/dashboard for application alerts.",
                },
                indent=2,
            )
        )
        sys.exit(0)

    capture = pyshark.LiveCapture(interface=args.interface)
    packets = []
    for packet in capture.sniff_continuously(packet_count=args.packet_count):
        packets.append(
            {
                "highest_layer": getattr(packet, "highest_layer", None),
                "length": getattr(packet, "length", None),
            }
        )

    print(
        json.dumps(
            {
                "interface": args.interface,
                "captured": len(packets),
                "packets": packets[:20],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
