"""Orchard P128Pow5T3 over Pallas, with pinned deployed constants.

rounds counts PARTIAL rounds: four original full rounds, the first r original
partial rounds, then the original final four full rounds (indices 60..63).
Full r=56 agrees with halo2_poseidon 0.2.0 ConstantLength<2>.
"""
from functools import lru_cache
import json
from pathlib import Path

from .errors import VerificationError


class PoseidonInputError(VerificationError):
    pass


P = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001


@lru_cache(maxsize=1)
def parameters():
    data = json.loads((Path(__file__).resolve().parents[1] / 'pareto/orchard-pallas-constants.json').read_text())
    return tuple(tuple(int(x, 16) for x in row) for row in data['round_constants']), tuple(tuple(int(x, 16) for x in row) for row in data['mds'])


def permute(state, rounds=56):
    if type(rounds) is not int or not 0 <= rounds <= 56:
        raise PoseidonInputError('Orchard requires 0..56 partial rounds')
    if len(state) != 3 or any(type(x) is not int or not 0 <= x < P for x in state):
        raise PoseidonInputError('requires three canonical Pallas field elements')
    constants, mds = parameters()
    state = list(state)
    for index in (*range(4), *range(4, 4 + rounds), *range(60, 64)):
        state = [(x + c) % P for x, c in zip(state, constants[index])]
        for column in (range(3) if index < 4 or index >= 60 else range(1)):
            state[column] = pow(state[column], 5, P)
        state = [sum(c * x for c, x in zip(row, state)) % P for row in mds]
    return tuple(state)


def digest(message: bytes, rounds: int) -> bytes:
    if not isinstance(message, bytes) or len(message) != 64:
        raise PoseidonInputError('Orchard input must be exactly two 32-byte little-endian field encodings')
    elements = [int.from_bytes(message[i:i+32], 'little') for i in (0, 32)]
    if any(x >= P for x in elements):
        raise PoseidonInputError('noncanonical Pallas field encoding (no reduction modulo p)')
    return permute((*elements, 1 << 65), rounds)[0].to_bytes(32, 'little')
