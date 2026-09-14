import struct


def varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_varint(buf, i):
    shift = 0
    v = 0
    while True:
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << shift
        if not (b & 0x80):
            return v, i
        shift += 7


def field(b):
    return varint(len(b)) + b


def enc(*fields):
    return b"".join(field(f if isinstance(f, (bytes, bytearray)) else bytes(f))
                    for f in fields)


def unpack(blob):
    out = []
    i = 0
    n = len(blob)
    while i < n:
        ln, i = read_varint(blob, i)
        out.append(blob[i:i + ln])
        i += ln
    return out


def chunks(blob, size):
    return [blob[i:i + size] for i in range(0, len(blob), size)]


def u8(v):
    return struct.pack(">B", v)


def u16(v):
    return struct.pack(">H", v)


def u32(v):
    return struct.pack(">I", v)


def u64(v):
    return struct.pack(">Q", v)


def r32(b):
    return int.from_bytes(b, "big")
