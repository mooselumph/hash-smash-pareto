# A distribution-free ordinary collision for 3-round BLAKE3

## Claim and scope

This package specifies a classical randomized algorithm for the exact target
`blake3-r3-prefix-v1`. On one processor its worst-case charged time is strictly
less than `2^129` target-compression units, its peak memory is strictly less
than `2^136` bytes, its preprocessing is strictly less than `2^124` of those
same units, and its probability of returning two distinct complete messages
with equal 256-bit digests is strictly greater than `0.39`. The probability is
over fresh independent algorithmic coins and a fixed target. It does not assume
that 3-round BLAKE3 is a random oracle, balanced, differentially uniform, or
pseudorandom. The claim reports worst-case upper bounds. It does not report a
measured runtime, and it supplies no collision witness.

The required identifier `blake3-r3-nominal-v2` is the organizer's nominal
reference, whose display value is 128. That reference is not an established
attack, not an executable baseline, and not a proved implementation cost. This
construction does not claim to beat 128. `ready` asks for review. It is not
qualification, a trusted score, or human acceptance.

The machine is the classical probabilistic 256-bit word RAM of
`collision-frontier-v5`. One 3-round BLAKE3 compression costs 1. Every other
primitive costs `1/C` with `C = 638`, the selected track's reference operation
cost for one instrumented 3-round compression. The primitives are a 256-bit
load or store, addition or subtraction modulo `2^256`, bitwise AND, OR, XOR or
NOT, a shift or rotation, a comparison, a conditional branch, and an
independent uniform 256-bit word. Instruction fetch is not in that list and is
not charged. Large integers that appear only in the analysis are not computed
by the algorithm.

There is one processor. Parallel wall-clock time is not the score. There is no
restart and no success amplification. Every unsuccessful sample is already
inside the `n` paid trials.

## Messages and the single compression

Let `n = 2^128`, `M = 2^256` and `d = 2^384`. In each of exactly `n` trials,
draw two fresh independent uniform 256-bit words `U` and `R`, and set
`V = R AND (2^128 - 1)`. The message is the 48-byte string whose first 32
bytes are `U` in little-endian order and whose last 16 bytes are the low 128
bits of `V` in little-endian order. Distinct pairs `(U, V)` are distinct
messages. The messages are uniform on a domain `D` of size `d`. Each has bit
length 384, which is below `2^64`.

A 48-byte string is one block of one chunk. The trusted `blake3` evaluation of
such a string performs exactly one compression:

- chaining value: the standard BLAKE3 IV
  `6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19`;
- message words: the 12 little-endian 32-bit lanes of the 48-byte string,
  followed by four zero words (zero fill is only the compression's word
  loading; those bytes are not part of the message);
- counter: 0, both at the chunk and at the root;
- block length: 48;
- flags: `CHUNK_START | CHUNK_END | ROOT = 11`.

There is no parent compression and no second chunk compression. For a single
block, the root flag is applied to that block's compression itself. The digest
is the first 32 little-endian bytes of the compression output, which are the
first eight feed-forward words `v[i] XOR v[i+8]`. No output bit is discarded.
Denote this complete-message function by `h` and the 256-bit integer formed by
those 32 bytes by `Y`. The eight `G` calls, the BLAKE3 message permutation
between rounds, the three prefix rounds, and the feed-forward are inside the
priced compression. Marshaling words into and out of that call is charged
below as ordinary work.

An internal chaining value, a free-start compression collision, or a keyed
hash is not accepted as success. Success is two different 48-byte strings whose
complete `h` values are equal.

## Algorithm

Use two arrays `A` and `B`, each of `n` records. A record is three 256-bit
words `(Y, U, V)`, with the high 128 bits of `V` equal to zero. Also use a
count array of `2^32` words. No hash table, no per-record pointer, and no
stored random tape is used. `R` is discarded after `V` is formed.

Zero `A` and `B`. For `t = 0, ..., n-1`, sample the message, compute `h` with
one compression, and store the record in `A`. Then sort `A` into nondecreasing
order of the full unsigned 256-bit key `Y` by an 8-pass stable radix sort on
32-bit digits, using `B` as the other buffer. Then scan adjacent records. The
following is the algorithm, not an experiment program.

```
zero A and B
for t = 0, ..., n-1:
    U = RANDOM256()
    R = RANDOM256()
    V = R AND (2^128 - 1)
    form the 16 message lanes and the IV, counter 0, block length 48, flags 11
    Y = COMPRESS3(IV, lanes, counter 0, block length 48, flags 11)
    A[t] = (Y, U, V)
src = A
dst = B
for p = 0, ..., 7:
    shift = 32 * p
    zero count[0 .. 2^32 - 1]
    for each record in src, in order:
        digit = (Y >> shift) AND (2^32 - 1)
        count[digit] = count[digit] + 1
    sum = 0
    for digit = 0, ..., 2^32 - 1:
        sum = sum + count[digit]
        count[digit] = sum
    for i = n-1, n-2, ..., 0:
        digit = (src[i].Y >> shift) AND (2^32 - 1)
        count[digit] = count[digit] - 1
        dst[count[digit]] = src[i]
    exchange src and dst
for k = 1, ..., n-1:
    if src[k-1].Y == src[k].Y and (src[k-1].U != src[k].U or src[k-1].V != src[k].V):
        rebuild both 48-byte messages
        recompute both complete hashes
        if the messages differ and the digests agree, return them
return FAILURE
```

The final check uses at most two further compressions. In this model it cannot
reject a genuine table match. It is not repeated. If no adjacent pair is a
distinct-input collision, the algorithm returns `FAILURE` after the paid work.
That work is inside the bound below. The scan may return at the first success;
the bound charges the full scan anyway.

The radix sort is least-significant-digit, stable, and exact on every input.
One-digit counting sort places equal digits in their previous relative order
because records are scattered from the end through exclusive prefix sums.
Eight digits cover all 256 bits of `Y`, so the final order is fully sorted.
Equal digests are therefore contiguous. If any equal-digest run contains two
different messages, some adjacent pair in that run differs in `(U, V)`:
otherwise the whole run would be one repeated message. The scan therefore
returns a distinct-input collision whenever the sample contains one. It does
not treat two copies of the same message as success.

## Success probability, for every function

Fix an arbitrary function `h` from `D` to a set of `M` labels. Sampling a
uniform input and applying `h` yields some output distribution `p_y`, possibly
far from uniform. The `n` inputs are independent, so the `n` outputs are
independent with distribution `p`. Let `e_n` be the elementary symmetric
polynomial of degree `n`. The probability that all `n` outputs are different is
`n! e_n(p_1, ..., p_M)`.

For any two coordinates `a` and `b`, and for the elementary symmetric
polynomials `A`, `B` and `E` of the remaining coordinates in degrees `n`,
`n-1` and `n-2`,

```
e_n = A + (a + b) B + a b E,    E >= 0.
```

Replacing `a` and `b` by their average keeps `a + b` fixed and replaces `a b`
by a value at least as large, because
`((a+b)/2)^2 - ab = (a-b)^2 / 4 >= 0`. Averaging therefore does not decrease
`e_n`. The probability simplex is compact, so `e_n` has a maximizer. Among
maximizers, choose one of minimum sum of squares. If two coordinates differ,
averaging them stays on the simplex and either increases `e_n`, which
contradicts maximality, or preserves `e_n` while strictly decreasing the sum of
squares, which contradicts the choice. Every coordinate is therefore equal.
The uniform vector is the unique such maximizer, including against vectors
with zeros. Hence, for every `h`,

```
Pr[all outputs differ] <= prod(i = 0, ..., n-1) (1 - i/M) <= exp(-n(n-1)/(2M)).
```

The product is the uniform case. The exponential bound is `1 - z <= exp(-z)`
for `0 <= z < 1`, from `log(1-z) <= -z`. No independence of pairwise collision
events was used. Consequently

```
Pr[some output repeats] >= 1 - exp(-n(n-1)/(2M)).
```

Let `E_in` be the event that two of the `n` inputs are equal. There are
`n(n-1)/2` unordered pairs, and each pair of uniform independent inputs agrees
with probability `1/d`, so `Pr[E_in] <= n(n-1)/(2d)`. On an output collision
outside `E_in`, the two inputs differ and the scan succeeds. Therefore

```
Pr[success] >= 1 - exp(-n(n-1)/(2M)) - n(n-1)/(2d).
```

This holds for every function into `M` labels, including this exact 3-round
BLAKE3. Substitute `n = 2^128`, `M = 2^256` and `d = 2^384`:

```
x = n(n-1)/(2M) = 1/2 - 2^{-129} > 499/1000,
n(n-1)/(2d) < 2^{-129}.
```

The Taylor terms with positive signs give a rational lower bound:

```
exp(x) > 1 + 499/1000 + (499/1000)^2 / 2 + (499/1000)^3 / 6
       = 9865254499 / 6000000000,
exp(-x) < 6000000000 / 9865254499.
```

The last fraction is strictly less than `609/1000`, because
`6000000000 * 1000 = 6000000000000` and
`609 * 9865254499 = 6007939989891`. Also `2^{-129} < 1/1000`. Hence

```
Pr[success] > 1 - 609/1000 - 1/1000 = 390/1000 = 0.39.
```

The same arithmetic gives a gap below `391/1000` before subtracting the input
term, and the input term is far smaller than `1/1000`. The bound is not an
extrapolation from a truncated digest, a shorter-round collision, or a seeded
generator. The ideal random-word primitive is the cost model's coin source.
A finite deterministic expansion of a short seed is not used, and is not
claimed to supply these coins.

## Operation ledger

All of the following bounds hold on every random tape. `H` is the number of
3-round compressions and `W` is the number of other primitives. The charged
time is `T = H + W/638`.

| Category | Compressions | Other primitives |
| --- | ---: | ---: |
| Zero both record arrays, and load code | 0 | `32 n + 2^24` |
| All `n` samples, marshaling and record stores | `n` | `160 n` |
| Eight radix passes, record traffic only | 0 | `384 n` |
| Adjacent scan | 0 | `48 n` |
| Count-array clear, prefix sums, final rebuild | 2 | `2^40` |
| Total | `n + 2` | `624 n + 2^24 + 2^40` |

Thus `H = n + 2` and `W <= 624 n + 2^24 + 2^40`. The code-load term is only the
`2^24` summand. The `2^40` summand is only the radix bookkeeping and the final
rebuild. They are not two names for the same work.

Zeroing. Each array holds `3n` words, so `6n` words are stored. One word costs
a store, a pointer addition, a comparison and a branch: 4 primitives, hence
`24 n`. The bound `32 n` covers that loop and its setup. Loading the fixed
program and the public IV, masks and flag constants costs at most `2^24`
primitives. This zeroing is preprocessing. It is also inside `T`.

Sampling costs at most 160 primitives per trial. The compression itself is not in this list. Packing its output is:

| Step | Primitives |
| --- | ---: |
| Draw `U` and `R`, then mask `V` | 3 |
| Eight lanes of `U`: address, shift, mask, store | 32 |
| Four lanes of `V`, likewise | 16 |
| Four zero lanes: address and store | 8 |
| Eight IV words: address, load, address, store | 32 |
| Store counter 0, block length 48 and flags 11 | 6 |
| Pack eight output lanes into `Y` | 33 |
| Store `(Y, U, V)` | 6 |
| Advance and test the trial index | 3 |
| Sum | 139 |

The cap `160` leaves room for a repeated address temporary. The schedule,
three rounds and feed-forward are the one priced compression, not a second
hash.

Radix traffic costs at most 48 primitives per record per pass. Records are
visited through a pointer that starts at the first word of the buffer. A
histogram step is: load `Y`; shift; mask; add the count-array base; load;
add one; store; add 3 to the source pointer; compare; branch. That is 10
primitives, charged as 16. A scatter step is: load `Y`; shift; mask; add the
count-array base; load; subtract one; store; copy that destination slot
(one bitwise OR with zero); shift and add to multiply the slot by 3; add the
destination base; for each of the three words, add the source offset, load,
add the destination offset, and store (12 primitives); add 3 to the source
pointer; subtract one from the loop index; compare; branch. That is
4 + 4 + 2 + 1 + 12 + 1 + 3 = 27 primitives, charged as 32. The source
stride is the added 3, not a second index multiplication. Each pass therefore
costs at most `48 n` primitives of record traffic, and eight passes cost
`384 n`. This does not include clearing or prefix-summing the count array.

Those bookkeeping loops are distribution-independent. Clearing `2^32` counters
costs at most 4 primitives each, and eight passes cost `2^37`. Each prefix
sum walks `2^32` counters at most 8 primitives each, and eight passes cost
`2^38`. The final message rebuild, digest comparison and output stores cost
well under `2^20`. The sum is below `2^40`.

The scan charges 48 primitives per adjacent pair, hence `48 n`. A pair needs
two digest loads and a compare/branch, four message-word loads and their
compares, the address additions for those loads, and the loop test. That is
under 30 primitives; 48 is the cap, including pairs that are skipped because
the messages match.

Thus

```
T <= n + 2 + (624 n + 2^24 + 2^40) / 638
   = (1262 n + 2^24 + 2^40 + 1276) / 638.
```

Since `2 * 638 = 1276`,

```
2^129 - T >= (14 n - 2^24 - 2^40 - 1276) / 638,
```

and `14 n = 14 * 2^128 > 2^24 + 2^40 + 1276`. Therefore `T < 2^129`. The claim
`time_log2 = 129` is this ceiling. It is not the bare sample exponent 128.
Preprocessing separately satisfies

```
P <= (32 n + 2^24) / 638 < 2^124,
```

because `32 * 2^128 = 512 * 2^124` and `638 * 2^124 - 512 * 2^124 = 126 * 2^124`,
which is larger than `2^24`. This `P` is already inside `T`. It is not added
again. No offline search builds a collision to hide in the program, and no
advice is generated.

## Memory, code and advice

Two record buffers occupy `2 * n * 3 * 32 = 192 n` bytes. The count array
occupies `2^32 * 32 = 2^37` bytes. Code, IV, masks, flags, counters and a
constant amount of compression scratch occupy at most `2^20` bytes. Peak live
storage is therefore at most

```
192 n + 2^37 + 2^20 < 256 n = 2^136
```

bytes, because `64 * 2^128 > 2^37 + 2^20`. Addresses of these arrays, including
`base + digit` for a 32-bit digit and `base + 3 * index` for an index below
`2^128`, are below `2^137` and fit in a 256-bit word. The products by 2 and 3
do not overflow a 256-bit word. The model allows this RAM. Physical hardware
is not claimed.

The program is uniform. Its only constants are the public IV, the public flags,
`n`, the masks and the radix parameters above. There is no target-dependent
advice and no stored collision. The schema field is logarithmic and
nonnegative, so `nonuniform_advice_log2_bytes = 0` means at most one byte,
which covers zero bytes of advice. It does not take a logarithm of zero, and
it does not hide the code already counted in the memory bound. No `data_log2`
field is used.

## What this argument does not use

No heuristic is declared. The success bound is a theorem about every function
from `D` to `M` labels, and the operation bounds hold on every tape by the
loop structure. A truncated-digest experiment is not evidence for this claim
and is not declared. An empty certificate manifest means that no concrete pair
is supplied; the algorithm's output is the pair when it succeeds.

A one-round cancellation is not reused. For a fixed incoming `(a, b, c, d)`,
the BLAKE2s `G` map on the two message words is injective. The outputs
determine the unique preimage:

```
b1 = ROR(b2, 25) XOR c2
c1 = c2 - d2
d1 = ROR(d2, 24) XOR a2
a1 = ROR(d1, 16) XOR d
x  = a1 - a - b
y  = a2 - a1 - b1
```

with subtraction modulo `2^32`. `ROR` is rotate-right. These invert the `G`
rotates: `b` was rotated right by 7, `d` by 8 and earlier by 16. If two
message pairs produced the same four outputs from the same incoming state,
both would equal this preimage. A nonzero message difference at one `G` with
identical incoming state cannot leave all four outputs unchanged, so it cannot
be absorbed and then ignored by later rounds. The priced compression still
runs all three rounds and the final root output. This observation is only a
reason not to import a one-round identity into this package. It is not a proof
that no faster 3-round attack exists.

## Limitations

The bound `2^129` is a proved ceiling for this radix-sort algorithm, not a
lower bound on 3-round BLAKE3 and not a claim that every implementation detail
was squeezed. The nominal display value 128 ignores marshaling, sorting and
memory traffic; this ledger counts them. Memory of `2^136` bytes is reported
and is not part of the score. No witness is given, and the full search is not
executed. The result is an algorithm with success probability above `0.39` on
the exact complete-message target.
