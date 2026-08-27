import sys
sys.path.insert(0, 'src/backend')
import decoders.iso8583 as mod

# Monkey-patch to trace
orig_parse = mod._parse_bitmap_bytes
def traced_parse(bb):
    r = orig_parse(bb)
    print(f'  _parse_bitmap_bytes({bb.hex()}) = {sorted(r)}')
    return r
mod._parse_bitmap_bytes = traced_parse

orig_llvar = mod._read_llvar
def traced_llvar(data, offset, binary_len=False):
    r = orig_llvar(data, offset, binary_len)
    print(f'  _read_llvar(offset={offset}, binary_len={binary_len}) = {r}')
    return r
mod._read_llvar = traced_llvar

orig_lllvar = mod._read_lllvar
def traced_lllvar(data, offset, binary_len=False):
    r = orig_lllvar(data, offset, binary_len)
    print(f'  _read_lllvar(offset={offset}, binary_len={binary_len}) = {r}')
    return r
mod._read_lllvar = traced_lllvar

payload = b'0100' + b'7220000000000000' + b'164111111111111111' + b'123456' + b'000000001000' + b'0131203030' + b'000001'
print('len:', len(payload))
r = mod._decode_at_offset(payload, False)
print('result:', r is not None)
if r:
    for k, v in r.items():
        if not k.startswith('iso8583.'):
            print(' ', k, '=', v)