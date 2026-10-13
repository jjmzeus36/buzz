"""Build the 1-second, 320x240 header-only MP4 used by quota upload tests.

Matches the validator's synthetic MP4 layout: no real media samples, external
tools, user data, or metadata. Intended to exercise admission after validation.
"""
import pathlib
import struct

def words(*values):
    return struct.pack('>' + 'I' * len(values), *values)

def shorts(*values):
    return struct.pack('>' + 'H' * len(values), *values)

def box(kind, payload=b''):
    return words(8 + len(payload)) + kind + payload

matrix = words(0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000)
mvhd = box(b'mvhd', words(0, 0, 0, 1000, 1000, 0x10000) + shorts(0x100) + bytes(10) + matrix + bytes(24) + words(2))
tkhd = box(b'tkhd', words(3, 0, 0, 1, 0, 1000) + bytes(16) + matrix + words(320 << 16, 240 << 16))
mdhd = box(b'mdhd', words(0, 0, 0, 1000, 1000) + bytes(4))
hdlr = box(b'hdlr', words(0, 0) + b'vide' + bytes(12) + b'VideoHandler\0')
vmhd = box(b'vmhd', words(1) + bytes(8))
dinf = box(b'dinf', box(b'dref', words(0, 1) + box(b'url ', words(1))))
avcc = box(b'avcC', bytes.fromhex('0142001effe10000010000'))
entry = bytes(6) + shorts(1) + bytes(16) + shorts(320, 240) + words(0x480000, 0x480000, 0) + shorts(1) + bytes(32) + shorts(24, 65535) + avcc
stbl = box(b'stbl', b''.join([
    box(b'stsd', words(0, 1) + box(b'avc1', entry)),
    box(b'stts', words(0, 1, 1, 1000)),
    box(b'stsc', words(0, 1, 1, 1, 1)),
    box(b'stsz', words(0, 0, 1, 0)),
    box(b'stco', words(0, 1, 28)),
]))
mdia = box(b'mdia', mdhd + hdlr + box(b'minf', vmhd + dinf + stbl))
mp4 = box(b'ftyp', b'isom' + words(0) + b'isom') + box(b'moov', mvhd + box(b'trak', tkhd + mdia)) + box(b'mdat')
pathlib.Path(__file__).with_name('minimal.mp4').write_bytes(mp4)
