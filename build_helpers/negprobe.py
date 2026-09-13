#!/usr/bin/env python3
"""Raw SMB2 NEGOTIATE probe.

Offers a chosen set of compression algorithms alongside the preauth-integrity,
encryption and netname contexts, and reports which contexts the server answers
with. NEGOTIATE is the first message on the connection, so no credentials are
involved.

Usage: negprobe.py <host> [port] [netname] [algos] [chained]

  algos    comma-separated compression algorithm ids, or "none" to omit the
           compression context entirely. Default 1,2,3,4,5.
  chained  the literal word "chained" to set SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED.

Always exits 0: it reports, it does not judge.
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

COMPRESSION_ALGOS = {
    0: "NONE",
    1: "LZNT1",
    2: "LZ77",
    3: "LZ77+Huffman",
    4: "Pattern_V1",
    5: "LZ4",
}


def pad8(buf):
    while len(buf) % 8:
        buf += b"\x00"
    return buf


def context(ctype, data):
    return pad8(struct.pack("<HHI", ctype, len(data), 0) + data)


def build_negotiate(netname, algos, chained):
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]

    # StructureSize, CreditCharge, Status, Command, CreditRequest, Flags,
    # NextCommand, MessageId, Reserved, TreeId, SessionId, Signature
    header = b"\xfeSMB" + struct.pack(
        "<HHIHHIIQIIQ16s", 64, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, b"\x00" * 16
    )
    assert len(header) == 64, len(header)

    ctxs = b""
    ctxs += context(CTX_PREAUTH, struct.pack("<HH", 1, 32) + struct.pack("<H", 1) + b"\x11" * 32)
    ctxs += context(CTX_ENCRYPTION, struct.pack("<H", 2) + struct.pack("<HH", 2, 1))
    ctx_count = 2
    if algos:
        data = struct.pack("<HHI", len(algos), 0, 1 if chained else 0)
        data += b"".join(struct.pack("<H", a) for a in algos)
        ctxs += context(CTX_COMPRESSION, data)
        ctx_count += 1
    ctxs += context(CTX_NETNAME, netname.encode("utf-16-le"))
    ctx_count += 1

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
        ctx_count,
        0,
    )
    for d in dialects:
        body += struct.pack("<H", d)
    body = pad8(header + body)[64:]

    return header + body + ctxs


def main():
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 445
    netname = sys.argv[3] if len(sys.argv) > 3 else host
    algo_arg = sys.argv[4] if len(sys.argv) > 4 else "1,2,3,4,5"
    chained = len(sys.argv) > 5 and sys.argv[5] == "chained"

    if algo_arg.lower() == "none":
        algos = []
    else:
        algos = [int(a) for a in algo_arg.split(",") if a.strip()]

    offered = [COMPRESSION_ALGOS.get(a, a) for a in algos]
    print(f"=== offered compression {offered}{' CHAINED' if chained else ''}")

    msg = build_negotiate(netname, algos, chained)
    try:
        s = socket.create_connection((host, port), timeout=15)
        s.sendall(struct.pack(">I", len(msg)) + msg)
        head = s.recv(4)
        if len(head) < 4:
            print("  no response")
            return
        total = struct.unpack(">I", head)[0]
        buf = b""
        while len(buf) < total:
            chunk = s.recv(total - len(buf))
            if not chunk:
                break
            buf += chunk
        s.close()
    except OSError as e:
        print(f"  connection failed: {e}")
        return

    status = struct.unpack("<I", buf[8:12])[0]
    if status != 0:
        print(f"  NEGOTIATE refused, status 0x{status:08X}")
        return

    dialect, ctx_count = struct.unpack("<H", buf[68:70])[0], struct.unpack("<H", buf[70:72])[0]
    ctx_offset = struct.unpack("<I", buf[124:128])[0]
    print(f"  dialect 0x{dialect:04X}, {ctx_count} contexts returned")

    off = ctx_offset
    for _ in range(ctx_count):
        ctype, dlen = struct.unpack("<HH", buf[off : off + 4])
        data = buf[off + 8 : off + 8 + dlen]
        name = CTX_NAMES.get(ctype, f"UNKNOWN(0x{ctype:04X})")
        extra = ""
        if ctype == CTX_COMPRESSION and dlen >= 8:
            count, _padding, flags = struct.unpack("<HHI", data[:8])
            got = struct.unpack(f"<{count}H", data[8 : 8 + 2 * count]) if count else ()
            extra = "  count={} flags=0x{:08X} algos={}".format(
                count, flags, [COMPRESSION_ALGOS.get(a, a) for a in got]
            )
        elif ctype == CTX_ENCRYPTION and dlen >= 4:
            extra = f"  cipher={struct.unpack('<H', data[2:4])[0]}"
        elif ctype == CTX_SIGNING and dlen >= 4:
            extra = f"  algo={struct.unpack('<H', data[2:4])[0]}"
        print(f"  - {name} (0x{ctype:04X}) dataLength={dlen}{extra}")
        off += 8 + dlen
        off += (-off) % 8


if __name__ == "__main__":
    main()
