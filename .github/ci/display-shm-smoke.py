#!/usr/bin/env python3
"""Connect to a running display-shm socket and check REGION handles work.

Sends HELLO, then reads messages until every region the WELCOME announced
has arrived with a descriptor, maps each descriptor and reads it.
Exit 0 on success, 1 on any failure.
"""
import array, mmap, os, socket, struct, sys, time

path = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(100):
    try:
        s.connect(path)
        break
    except OSError:
        time.sleep(0.1)
else:
    sys.exit("cannot connect to " + path)
s.settimeout(10)
# HELLO: type 1, flags 0, seq 0, version 3, caps 0, pid, reserved, uuid, reserved
s.sendall(struct.pack("<HHIIII16sQ", 1, 0, 0, 3, 0, os.getpid(), 0, bytes(16), 0))

regions = 0
control = None
deadline = time.time() + 20
while time.time() < deadline:
    fds = array.array("i")
    try:
        hdr, anc, _, _ = s.recvmsg(8, socket.CMSG_LEN(4))
    except socket.timeout:
        break
    if not hdr:
        sys.exit("QEMU closed the socket before sending a region")
    for lvl, typ, data in anc:
        if lvl == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            fds.frombytes(data[:len(data) - len(data) % 4])
    t = struct.unpack("<H", hdr[:2])[0]
    size = {0x81: 64, 0x82: 56, 0x83: 16, 0x84: 16, 0x85: 8}.get(t)
    if size is None:
        sys.exit("unknown message type 0x%x" % t)
    body = b""
    while len(body) < size - 8:
        body += s.recv(size - 8 - len(body))
    msg = hdr + body
    if t == 0x81:
        if len(fds) != 1:
            sys.exit("WELCOME carried %d descriptors" % len(fds))
        nheads = struct.unpack_from("<I", msg, 16)[0]
        m = mmap.mmap(fds[0], os.fstat(fds[0]).st_size)
        magic = struct.unpack_from("<I", m, 0)[0]
        print("WELCOME: %d head(s), control magic 0x%x, %d bytes"
              % (nheads, magic, len(m)))
        if magic != 0x33535347:
            sys.exit("bad control magic")
        control = nheads
    elif t == 0x82:
        if len(fds) != 1:
            sys.exit("REGION carried %d descriptors" % len(fds))
        size_r = struct.unpack_from("<Q", msg, 24)[0]
        m = mmap.mmap(fds[0], size_r)
        m[0:1]  # touch the mapping
        print("REGION: %d bytes mapped" % size_r)
        regions += 1
        if control is not None and regions >= control:
            break
if control is None or regions < 1:
    sys.exit("no WELCOME or no REGION arrived")
print("ok: %d region(s) with working descriptors" % regions)
