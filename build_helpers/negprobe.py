#!/usr/bin/env python3
"""Raw SMB2 NEGOTIATE probe.

Offers preauth-integrity, encryption, compression and netname negotiate
contexts and reports which ones the server answers with. Unauthenticated:
NEGOTIATE is the first message on the connection, so no credentials are
involved.
"""
import socket
import struct
import sys
import uuid

CTX_PREAUTH = 0x0001
CTX_ENCRYPTION = 0x0002
CTX_COMPRESSION = 0x0003
CTX_NETNAME = 0x0005
CTX_TRANSPORT = 0x0006
CTX_RDMA = 0x0007
CTX_SIGNING = 0x0008
CTX_POSIX = 0x0100

CTX_NAMES = {
    CTX_PREAUTH: "PREAUTH_INTEGRITY",
    CTX_ENCRYPTION: "ENCRYPTION",
    CTX_COMPRESSION: "COMPRESSION",
    CTX_NETNAME: "NETNAME",
    CTX_TRANSPORT: "TRANSPORT",
    CTX_RDMA: "RDMA_TRANSFORM",
    CTX_SIGNING: "SIGNING",
    CTX_POSIX: "POSIX_EXTENSIONS",
}

COMPRESSION_ALGOS = {0: "NONE", 1: "LZNT1", 2: "LZ77", 3: "LZ77+Huffman", 4: "Pattern_V1", 5: "LZ4"}


def pad8(buf):
    while len(buf) % 8:
        buf += b"\x00"
    return buf


def context(ctype, data):
    return pad8(struct.pack("<HHI", ctype, len(data), 0) + data)


def build_negotiate(netname):
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]

    # StructureSize, CreditCharge, Status, Command, CreditRequest, Flags,
    # NextCommand, MessageId, Reserved, TreeId, SessionId, Signature
    header = b"\xfeSMB" + struct.pack(
        "<HHIHHIIQIIQ16s", 64, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, b"\x00" * 16
    )
    assert len(header) == 64, len(header)

    fixed_len = 36 + 2 * len(dialects)
    ctx_offset = 64 + fixed_len
    ctx_offset += (-ctx_offset) % 8

    body = struct.pack(
        "<HHHHI16sIHH",
        36,
        len(dialects),
        0x0001,  # SecurityMode: signing enabled
        0,
        0x0000007F,  # every capability bit the spec defines
        uuid.uuid4().bytes,
        ctx_offset,
        4,
        0,
    )
    for d in dialects:
        body += struct.pack("<H", d)
    body = pad8(header + body)[64:]

    ctxs = b""
    ctxs += context(CTX_PREAUTH, struct.pack("<HH", 1, 32) + struct.pack("<H", 1) + b"\x11" * 32)
    ctxs += context(CTX_ENCRYPTION, struct.pack("<H", 2) + struct.pack("<HH", 2, 1))
    ctxs += context(
        CTX_COMPRESSION,
        struct.pack("<HHI", 4, 0, 0) + struct.pack("<HHHH", 1, 2, 3, 4),
    )
    ctxs += context(CTX_NETNAME, netname.encode("utf-16-le"))

    return header + body + ctxs


def main():
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 445
    netname = sys.argv[3] if len(sys.argv) > 3 else host

    msg = build_negotiate(netname)
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(struct.pack(">I", len(msg)) + msg)

    head = s.recv(4)
    if len(head) < 4:
        print("no response")
        return 1
    total = struct.unpack(">I", head)[0]
    buf = b""
    while len(buf) < total:
        chunk = s.recv(total - len(buf))
        if not chunk:
            break
        buf += chunk
    s.close()

    status = struct.unpack("<I", buf[8:12])[0]
    print(f"response {len(buf)} bytes, status 0x{status:08X}")
    if status != 0:
        return 1

    (
        struct_size,
        sec_mode,
        dialect,
        ctx_count,
    ) = struct.unpack("<HHHH", buf[64:72])
    caps = struct.unpack("<I", buf[88:92])[0]
    ctx_offset = struct.unpack("<I", buf[124:128])[0]
    print(f"dialect 0x{dialect:04X}  securityMode 0x{sec_mode:04X}  caps 0x{caps:08X}")
    print(f"negotiate contexts returned: {ctx_count} (offset {ctx_offset})")

    off = ctx_offset
    for _ in range(ctx_count):
        ctype, dlen = struct.unpack("<HH", buf[off : off + 4])
        data = buf[off + 8 : off + 8 + dlen]
        name = CTX_NAMES.get(ctype, f"UNKNOWN(0x{ctype:04X})")
        extra = ""
        if ctype == CTX_COMPRESSION and dlen >= 8:
            count, _padding, flags = struct.unpack("<HHI", data[:8])
            algos = struct.unpack(f"<{count}H", data[8 : 8 + 2 * count]) if count else ()
            extra = "  count={} flags=0x{:08X} algos={}".format(
                count, flags, [COMPRESSION_ALGOS.get(a, a) for a in algos]
            )
        elif ctype == CTX_ENCRYPTION and dlen >= 4:
            count = struct.unpack("<H", data[:2])[0]
            extra = f"  cipher={struct.unpack('<H', data[2:4])[0]}"
        elif ctype == CTX_SIGNING and dlen >= 4:
            extra = f"  algo={struct.unpack('<H', data[2:4])[0]}"
        print(f"  - {name} (0x{ctype:04X}) dataLength={dlen}{extra}")
        off += 8 + dlen
        off += (-off) % 8

    return 0


if __name__ == "__main__":
    sys.exit(main())
