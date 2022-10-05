#/usr/bin/env python3


import sys, os
import struct
import datetime
import collections

# https://wiki.wireshark.org/Development/LibpcapFileFormat
# Layout Pcap-file:
# Global Header | Packet Header | Packet Data | Packet Header | Packet Data | ...

GblHdr = collections.namedtuple('GblHdr', [ 'magic_number', 'version_major', 'version_minor', 'thiszone', 'sigflags', 'snaplen', 'network' ])
PktHdr = collections.namedtuple('PckHdr', [ 'ts', 'ts_sec', 'ts_usec', 'incl_len', 'orig_len' ])
kGblHdrFmt = '<IHHiIII'; kGblHdrSiz = struct.calcsize(kGblHdrFmt)
kPktHdrFmt = '<IIII';    kPktHdrSiz = struct.calcsize(kPktHdrFmt)
    
def open_offline(fname):
    with open(fname, 'rb') as fp:
        data = fp.read(kGblHdrSiz)
        if len(data) != kGblHdrSiz: raise ValueError('Unable to read Pcap Global Header')
        _gblHdr = struct.unpack(kGblHdrFmt, data)
        gblHdr = GblHdr(*_gblHdr)
        assert(gblHdr.magic_number == 0xa1b2c3d4); assert(gblHdr.version_major == 2); assert(gblHdr.version_minor == 4)

        while True:
            data = fp.read(kPktHdrSiz)
            if data == b'': return # Eof
            if len(data) != kPktHdrSiz: raise ValueError('Unable to read Pcap Record Header')
            _hdr = struct.unpack(kPktHdrFmt, data)
            _ts = datetime.datetime.utcfromtimestamp(_hdr[0]+_hdr[1]*0.000001)
            hdr = PktHdr(_ts, *_hdr)

            pkt = b''
            while len(pkt) < hdr.incl_len:
                data = fp.read(hdr.incl_len-len(pkt))
                if data == '': raise ValueError('Unable to read Pcap Packet')
                pkt += data
            yield hdr, pkt
                


if __name__ == '__main__':
    fname = sys.argv[1] if len(sys.argv) > 1 else 'xsupport.pcap'
    i=1
    for hdr, pkt in open_offline(fname):
        print(hdr)
        i=i+1

    print(i)
