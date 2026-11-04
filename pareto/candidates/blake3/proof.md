# A bounded-memory, distribution-free collision construction for BLAKE3-r3

## 1. Scope and status

This is an initial generic construction, not new differential cryptanalysis and
not an improvement over the organizer's nominal 128-bit display. There is no
qualified incumbent in the observed live submission history. The required
baseline identifier is metadata only. The finite algorithm below establishes a
candidate point (3,246) on the round/normalized-time-memory axes. It requires
astronomical time; no full-scale execution or concrete collision is claimed.
The success bound is unconditional for the fixed target, over fresh independent
random coins. There are no random-oracle, independence-of-differentials, or
uniform-output assumptions and no experiments are needed for this argument.

## 2. Exact hash and message domain

Let F map 64-byte strings to the complete first 32 output bytes of standard
unkeyed BLAKE3 with exactly prefix rounds 0,1,2 in every compression. All messages
here have exactly 512 bits, strictly below 2^64. The standard IV, G function,
message permutation, little-endian encoding and feed-forward are preserved.
For a single full 64-byte block there is one chunk and no parent. Compute its
root output directly with input CV equal to the standard IV, block length 64,
output counter zero, and flags CHUNK_START|CHUNK_END|ROOT = 11. Use the first eight
little-endian words of the compression output. This is the complete hash of this
message, not equality of intermediate chaining values. No separate chunk CV
compression is necessary: the sole final chunk block becomes the root Output.
Every use of F therefore costs exactly one selected-round target compression.

## 3. Concrete finite randomized algorithm

Set N=2^256, q=8192 and R=ceil(N/(q*(q-1))). Store q records of exactly 96 bytes:
a 32-byte digest and its complete 64-byte message. For batches numbered 0 through
R-1, independently generate q messages by drawing two independent uniform 256-bit
words per message. Compute F and store the record. Sort records in place by their
unsigned 256-bit digest using the conventional binary max-heapsort below. Scan
each equal-digest run, retaining its first message as representative. Compare
every subsequent message in that run with the representative; if they differ,
recompute both complete hashes and output the two messages after confirming
equality. Otherwise continue. If every batch fails, return failure. Stop at the
first valid pair. Duplicate identical messages never count as success.

Heapsort uses a zero-based array. First call sift(i,q) for i=floor(q/2)-1 down to
zero. Then for end=q-1 down to 1, exchange records 0 and end and call sift(0,end).
The second argument is the exclusive heap limit. In sift(i,end), set left=2*i+1;
if left>=end return. Choose the child with larger digest among left and left+1
when the latter exists. If the parent's digest is at least the child's, return;
otherwise exchange the two full records, set i=child and repeat. Digest ties may
be resolved arbitrarily. All indexing, counters and digest comparisons fit a
256-bit word. Equal-digest runs become consecutive irrespective of tie order.

## 4. Success probability without a hash heuristic

Write p_y=Pr[F(M)=y] for an independent uniform 64-byte message M. There are N
possible outputs. For iid samples, the probability that all q outputs differ is
q! times the elementary symmetric polynomial e_q(p_1,...,p_N). It is maximized
by p_y=1/N. To see this, fix all but two coordinates a,b with their sum fixed:
e_q = ab*A + (a+b)*B + D, with A,B,D nonnegative and independent of a,b. Replacing
a,b by their average cannot decrease e_q. On the compact simplex a maximizer
exists; repeated averaging, or the usual symmetric-polynomial smoothing limit,
reaches the uniform vector without decreasing its value. Thus

Pr[no digest repeat in a batch] <= (N)_q/N^q
 <= exp(-q*(q-1)/(2*N)).

The final inequality follows by multiplying 1-i/N and using 1-x<=exp(-x).
Fresh batch coins are independent for this fixed deterministic F. Therefore the
probability of at least one digest repeat anywhere in the R batches is at least
1-exp(-R*q*(q-1)/(2*N)) >= 1-exp(-1/2).

A digest repeat might consist only of equal messages. Union bound the probability
of any identical-message pair within any batch by

R*q*(q-1)/(2*2^512).

Since R <= N/(q*(q-1))+1 this is at most
2^-257 + q*(q-1)/2^513 < 2^-256.
No union bound across different batches is needed: only within-batch repeats are
used. Consequently the probability of a distinct-message collision found by the
algorithm is at least 1-exp(-1/2)-2^-256 > 0.3934 > 0.39. This argument holds even
for a very biased or constant F. The scan finds any equal-digest run containing
two distinct messages: if all messages equal the representative they are all
identical; otherwise the first differing one supplies the pair. Full verification
cannot reject a correctly computed collision.

## 5. Primitive-operation accounting

Use the selected-round contract C=638 word operations per target compression.
Charge random 256-bit generation, memory operations, index arithmetic,
comparisons, conditional branches and all loop control. There are at most q
compressions per batch plus at most two final verification compressions overall.
The deterministic, conservative other-operation cap is W_batch < 2^24.
Here is a finite derivation rather than a claim of unit-cost sorting:

A sift level uses at most 64 primitive word operations. The left index takes
shift/add; child bounds and digest selection take at most eight operations
including loads, comparisons and branches; the parent check takes at most five;
a full record swap takes 12 loads/stores across three words per record, plus
address calculations; index updates, address arithmetic and loop tests fit the
remaining allowance. Addressing a record at base+96*i needs shift/add and is
charged even though ordinary indexed loads could hide it. All temporary values
fit fewer than 32 words. A terminating sift call adds at most 32 operations.

There are fewer than 2q sift calls and no call has more than 13 levels. Thus all
sift work is less than (2*q)*(13*64+32) = 14,155,776 primitive operations.
Each extraction swap and its loop control use at most 64 further operations,
for fewer than 524,288 operations. Generating/storing/hashing-input preparation
uses at most 64 non-compression operations per record, including two independent
random draws, writing the three-word record and IV/flags setup. This adds at
most 524,288. Scanning equal runs, reading and comparing two-word messages,
updating representative indices and loop controls adds at most 64q=524,288.
Batch initialization, resetting the table, incrementing and comparing the batch
counter and any remaining per-batch work are bounded by 4096 operations.
Total is at most 16,232,736 < 16,777,216 = 2^24. Target compression internals are
already charged as compressions and are not counted twice. Table clearing is
unnecessary because every record is overwritten; even an extra clear fits slack.

Uniform preprocessing consists only of calculating constants and setting up the
fixed table and code, bounded by 2^20 primitive operations. R can be calculated
by 256-bit long division in well under that allowance, or hardcoded as a
uniform constant derived from N and q. Final recovery, two verification hashes,
output copies and termination take at most two compressions plus 2^16 primitive
operations. No omitted attack search, precomputed collision, stored random tape,
or nonuniform advice is used. All failed batches and fresh randomness are
included. The algorithm is sequential; no parallel latency discount is used.

As q*(q-1)>2^25, R < 2^231. Each batch costs at most
8192 + 2^24/638 < 2^16 compression units. Therefore

T < 2^231*2^16 + 2 + (2^20+2^16)/638 < 2^248.

For the sharper bound actually claimed, q*(q-1) > (1-2^-13)*2^26,
so R < 1.001*2^230, while 8192+2^24/638 < 35000. Hence
T < 35035*2^230 + 2000 < 65536*2^230 = 2^246.
The claim time_log2=246 is a rounded-up upper bound, not an expectation or
wall-clock estimate. Preprocessing_log2=11 bounds preprocessing in compression
units (2^20/638 < 2^11); finalization is included in total time.

## 6. Memory and advice

The sole record array uses 8192*96=786432 bytes. Reserve a further 262144 bytes
for code, literal constants, root compression state, the batch counter, sift
scratch, output messages and fixed control data. An iterative sift has no
recursion and needs at most 32 temporary 256-bit words. The full iterative
program described here fits comfortably in the reserved code budget; no Python
interpreter, OS process memory, sort library, arbitrary precision library or
retained random tape is part of the abstract word-RAM implementation. This is
a constructive pseudocode algorithm in the stipulated computation model, not
a resource claim for running a high-level host interpreter. Thus total live
memory is at most 1048576 bytes and memory_log2_bytes=20. The code and all
constants are uniform; no nonuniform advice is required (the schema's value
zero is a conservative one-byte upper bound for zero required advice).
The normalized cost equals 246+max(0,20-20)=246.

## 7. Evidence and limitations

The probability and resource arguments above are the evidence. No participant
Python is submitted or executed, no external citation is needed, and the empty
certificate manifest asserts no collision witness. This is a complete finite
construction with success at least 0.39; it is not a report that this machine has
completed the astronomical attack. Setup/mechanical validity, AI qualification,
frontier inclusion and manual human publication remain separate decisions.
This initial generic point leaves very substantial room for reduced-round
cryptanalysis or sharper generic algorithms. In particular it does not establish
that three-round BLAKE3 has 246-bit collision security or that the nominal
128-bit reference has been beaten.
