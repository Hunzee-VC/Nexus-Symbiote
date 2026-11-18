"""Bring loopback up inside a fresh network namespace, then exec the command.

``unshare -n`` leaves ``lo`` down; a tool that talks to its own helper process over
127.0.0.1 needs it up. No other interface exists, so nothing beyond the host is reachable.
"""

import fcntl
import os
import socket
import struct
import sys

SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_UP = 0x1

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        request = struct.pack("16sH22x", b"lo", 0)
        flags = struct.unpack("16sH22x", fcntl.ioctl(control, SIOCGIFFLAGS, request))[1]
        fcntl.ioctl(control, SIOCSIFFLAGS, struct.pack("16sH22x", b"lo", flags | IFF_UP))
    os.execvp(sys.argv[1], sys.argv[1:])  # noqa: S606 - the argv comes from a reviewed adapter
