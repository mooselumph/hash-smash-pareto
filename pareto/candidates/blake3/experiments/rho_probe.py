"""Finite salted projected-walk evidence; full-output equality is not claimed."""
import hashlib
import json
import struct
import sys

IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
PERM = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
MASK32 = (1 << 32) - 1


def ror(v, r):
    return ((v >> r) | (v << (32-r))) & MASK32


def g(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & MASK32
    v[d] = ror(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & MASK32
    v[b] = ror(v[b] ^ v[c], 12)
    v[a] = (v[a] + v[b] + y) & MASK32
    v[d] = ror(v[d] ^ v[a], 8)
    v[c] = (v[c] + v[d]) & MASK32
    v[b] = ror(v[b] ^ v[c], 7)


def root(salt_words, state):
    # Exactly one 64-byte complete unkeyed BLAKE3-r3 root block.
    words = list(salt_words) + [state & MASK32, state >> 32] + [0]*6
    v = list(IV) + list(IV[:4]) + [0, 0, 64, 11]
    for _ in range(3):
        g(v, 0, 4, 8, 12, words[0], words[1])
        g(v, 1, 5, 9, 13, words[2], words[3])
        g(v, 2, 6, 10, 14, words[4], words[5])
        g(v, 3, 7, 11, 15, words[6], words[7])
        g(v, 0, 5, 10, 15, words[8], words[9])
        g(v, 1, 6, 11, 12, words[10], words[11])
        g(v, 2, 7, 8, 13, words[12], words[13])
        g(v, 3, 4, 9, 14, words[14], words[15])
        words = [words[i] for i in PERM]
    return v[0] ^ v[8]


def trial(seed, bits):
    seed_bytes = bytes.fromhex(seed)
    salt = seed_bytes
    sw = struct.unpack('<8I', salt)
    mask = (1 << bits) - 1
    start = int.from_bytes(hashlib.sha256(b'rho-start' + seed_bytes).digest(), 'little') & mask
    limit = 3 * (1 << (bits//2 - 1))
    cache = {}

    def f(x):
        # Memoization is experiment-only. It does not support claimed attack cost.
        if x not in cache:
            cache[x] = root(sw, x) & mask
        return cache[x]

    slow = start
    fast = start
    found = False
    for _ in range(limit):
        slow = f(slow)
        fast = f(f(fast))
        if slow == fast:
            found = True
            break
    if not found:
        return None, None
    left = start
    right = slow
    if left == right:
        return None, None
    for _ in range(limit):
        pred_left, pred_right = left, right
        left, right = f(left), f(right)
        if left == right:
            if pred_left == pred_right:
                return None, None
            a = salt + pred_left.to_bytes(32, 'little')
            b = salt + pred_right.to_bytes(32, 'little')
            return a.hex(), b.hex()
    return None, None


def main():
    req = json.load(sys.stdin)
    widths = {'rho12': 12, 'rho16': 16}
    bits = widths[req['experiment_id']]
    rows = []
    for row in req['trials']:
        a, b = trial(row['seed'], bits)
        rows.append({'trial': row['trial'], 'message_a_hex': a,
                     'message_b_hex': b})
    json.dump({'schema_version': 1, 'trials': rows}, sys.stdout,
              sort_keys=True, separators=(',', ':'))


if __name__ == '__main__':
    main()
