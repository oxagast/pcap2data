import sys; sys.path.insert(0, 'src/backend')
from scapy.all import rdpcap, TCP
pkts = rdpcap('samples/pcaps/s7comm_reading_plc_status.pcap')
for i, p in enumerate(pkts[:15]):
    if not p.haslayer(TCP): continue
    pl = bytes(p[TCP].payload)
    if len(pl) < 14 or pl[0] != 0x03: continue
    ss = 4 + 1 + pl[4]
    if ss + 12 >= len(pl) or pl[ss] != 0x32: continue
    r = pl[ss+1]
    if r not in (1, 3): continue
    if r == 1:
        plen = int.from_bytes(pl[ss+6:ss+8], 'big')
        dlen = int.from_bytes(pl[ss+8:ss+10], 'big')
        param_start = ss + 10
    else:
        ec = pl[ss+6]; er = pl[ss+7]
        plen = int.from_bytes(pl[ss+8:ss+10], 'big')
        dlen = int.from_bytes(pl[ss+10:ss+12], 'big')
        param_start = ss + 12
    pbyte = pl[param_start]
    print(f'Pkt {i}: rosctr={r} pbyte=0x{pbyte:02x} plen={plen} dlen={dlen}')
    if pbyte == 0xf0:
        amq_c = int.from_bytes(pl[param_start+2:param_start+4], 'big')
        amq_d = int.from_bytes(pl[param_start+4:param_start+6], 'big')
        pdu_s = int.from_bytes(pl[param_start+6:param_start+8], 'big')
        print(f'  Setup: AMQ_caller={amq_c} AMQ_called={amq_d} PDU_size={pdu_s}')
        print(f'  hex: {pl[param_start:param_start+10].hex()}')
    elif pbyte == 0x04:
        print(f'  Read: hex={pl[param_start:param_start+12].hex()}')