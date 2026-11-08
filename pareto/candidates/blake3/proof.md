# Sparse-checkpoint salted rho for complete BLAKE3-r3

1. Scope and result. This is a classical ordinary collision construction for
complete unkeyed BLAKE3 with prefix rounds 0,1,2 in every compression. It uses
one explicit fixed-target heuristic H-cap511. Conditional on that premise,
its success probability is at least 0.39. Its deterministic total work is below
2^128.217 selected-target compression units, including failures, and all memory
is at most 2^20 bytes. Consequently its normalized time-memory cost is 128.217.
This is a conditional generic construction, not a full-width executed collision,
unconditional security theorem, new differential, or human-accepted result.
The submitted finite probes have not been executed locally. Their source is
provided for trusted organizer execution; no favorable observation is asserted.

2. Exact complete target. Let F be the selected complete BLAKE3-r3 hash with
standard fixed IV, unkeyed mode, standard schedule and feed-forward. For salt S
and state x, each an unsigned 256-bit word, define M_S(x)=LE32(S)||LE32(x), where
LE32 denotes exactly 32 little-endian bytes. Define f_S(x)=LEinteger(F(M_S(x))).
The message has exactly 64 bytes, so the complete target is one root compression
with CV=IV, counter=0, true block length=64, flags CHUNK_START|CHUNK_END|ROOT=11.
Its output is all eight first 32-bit words, little-endian, not an internal CV.
Every target call uses prefix rounds 0,1,2 and the standard between-round message
permutation. No tree parent or additional root call exists for these one-block
messages. Salt is part of the ordinary message; it changes neither key nor IV.
For fixed S the injection is one-to-one. Equal full f_S values at distinct
predecessors therefore produce two distinct ordinary messages with equal entire
256-bit digests. Both messages satisfy the finite-byte-string domain below
2^64 bits. Near-collisions, changed IVs, truncated target outputs and free starts
are not accepted by the full attack.

3. Coins, parameters and data structures. Draw S,x0 independently uniformly from
all 256-bit words, using two priced random-word draws. Set N=2^256, D=2^119, m=511*D, and B=m+D=2^128. Execute one bounded attempt. There are no restarts,
parallel processors, advice or retained external precomputation. Counters and
states fit 256-bit words. Let x_i=f_S^i(x0). Store chronological checkpoints at indices aD for 0<=a<=510.
The searchable records omit index zero and all indices at least m.
Use a chronological array C[a]=x_(aD) and a separate sorted array of records
(state,index), with the actual orbit index in the second word. Each state/index
record uses two 32-byte RAM words. For n searchable records, build a perfect tree at height h=bit_length(n),
with n real records first in inorder followed by padding (U,NONE), where
U=2^256-1. A real U precedes padding. The n=0 case has no tree.
Section 10 specifies the dynamic layout and lookup; rebuild after insertion.
Only checkpoints, not all intermediate orbit states, are retained.

4. Concrete detection and recovery controller. Initially C[0]=x0 and the sorted
array is empty; initialize K,J with padding before detection. Set x=x0. Execute the following finite loops, with bounds
and all failure paths exactly as specified. A lookup returns an exact matching
state's index or NONE; it never tests only a digest projection in the full attack.

    for j = 1,...,B:
        x = f_S(x)
        k = eytzinger_lookup(x)
        if k is not NONE:
            goto RECOVER
        if j == B: return FAILURE
        if j mod D == 0 and j < m:
            append x to C
            sorted_insert(x,j)
    return FAILURE
    RECOVER:
        if k == 0: return FAILURE
        q = floor((j-D)/D)*D
        if q < 0 or q >= m: return FAILURE
        left = C[k/D-1]
        right = C[q/D]
        for h = q+1,...,j-D:
            right = f_S(right)
        if left == right: return FAILURE
        for h = 1,...,D:
            a = left; b = right
            left = f_S(left); right = f_S(right)
            if left == right:
                if a == b: return FAILURE
                A=M_S(a); Bmsg=M_S(b)
                recompute full F(A),F(Bmsg)
                if A != Bmsg and F(A)==F(Bmsg): return (A,Bmsg)
                return FAILURE
        return FAILURE

Every loop and recovery is bounded, even outside the sufficient success event.
At any hit k>0, the checkpoint index is a positive multiple of D less than j.
Thus j>D. The q guard rejects the terminal boundary q=m before any
array access; every remaining q is a retained chronological checkpoint strictly
less than j. At most D-1 right-pointer advances precede the final recovery loop.
The full-output verification is charged even though correctness already implies
it. No null row, pure cycle, cap failure or failed verification is retried.

5. Deterministic correctness and sufficient event. For any fixed S,x0 the orbit
has tail mu>=0 and cycle lambda>=1. The first mu+lambda states are distinct,
and x_(mu+lambda)=x_mu. Consider the event
    E: mu>0, lambda>=D, mu+lambda<=m.
Let k=ceil(mu/D)*D. Then mu<=k<mu+D<=mu+lambda, so this is the earliest
checkpoint inside the cycle, and k>=D. Every earlier checkpoint is on the tail
and can never be revisited. Every later cycle checkpoint has a strictly later
first revisit. Consequently the first exact checkpoint hit occurs at
j=k+lambda <=mu+lambda+D <=m+D=B, at the record with index k. Before that hit
all checkpoints in question have been inserted. Indeed lambda>=D and
mu+lambda<=m imply mu<=m-D and ceil(mu/D)*D<=m-D. Thus the needed k is a
positive checkpoint strictly below m; omitting zero and indices at least m
cannot change this successful hit. Chronological index zero remains available
for recovery. Removing searchable checkpoints cannot create an earlier hit. No earlier return or spurious
duplicate can preempt the hit, since any equal orbit states are cycle states.

Now left starts at x_(k-D), whose index is strictly below mu. The reconstructed
right pointer equals x_(j-D)=x_(k-D+lambda). Its chronological starting checkpoint
q=floor((j-D)/D)*D is retained: j=k+lambda<mu+D+lambda<=m+D,
so j-D<m and q<m. It was inserted before j (or is initial index zero); fewer
than D advances reconstruct the right pointer.
The pointers agree after exactly mu-(k-D) advances, an integer in [1,D]. Prior
to that advance the left pointer is on the nonrepeating tail and the right
pointer is strictly later in the orbit; therefore they cannot already agree.
After the final advance both are x_mu, since they are separated by lambda and
are then on the cycle. Their saved predecessors are distinct and map to the
same full f_S value. Injection of M_S gives a valid ordinary complete collision.
Thus E implies success. Outside E any returned pair still passes full target
verification, so no false collision can be output. Pure cycles may now hit a positive checkpoint, but cannot produce a false
collision because predecessor distinctness and full-target verification remain
mandatory. They are outside the sufficient success event.

6. Explicit score-critical premise H-cap511. For this fixed F and exact
salted 64-byte injection, over independent uniform full-width S,x0, posit
    Pr[mu>0 AND lambda>=2^119 AND mu+lambda<=511*2^119] >=0.39.
Section 5 then proves algorithmic success at least 0.39. This is a distributional
premise about actual fixed-target walks, not reviewer confidence, not a theorem
from independent coins, and not a claim that reduced BLAKE3 is ideal against
all attacks. A family of permutations, unusually long tails/cycles, or excessive
short cycles could violate it. The resource bound below holds whether it is
true or false. Its added cycle-length condition differs from the preceding
Floyd candidate; prior qualification does not establish this premise.

7. Finite random-mapping supporting calculation. For an independent uniform map
g on N states and uniform start, exposing fresh outputs until the first repeat
gives no-repeat probability product_(i=1)^m(1-i/N). Thus
    Pr[mu+lambda<=m] >=1-exp(-m*(m+1)/(2*N)).
The probability that the first repeat hits x0 within m transitions is at most
m/N. To bound short cycles, at any first-repeat transition i<=m the earlier
states whose indices yield lambda<D number at most D-1. Each fresh output is
uniform, so a union bound gives probability at most m*(D-1)/N for such a repeat.
Subtracting both excluded events (overlap only weakens this lower bound),
    Pr[E] >=1-exp(-m*(m+1)/(2*N))-m/N-m*(D-1)/N
           =1-exp(-m*(m+1)/(2*N))-m*D/N
           >1-exp(-(511/512)^2/2)-511/262144
           >0.3903354 >0.39.
This is a finite inequality, not an asymptotic approximation. In a random oracle
on 64-byte messages, distinct salts select disjoint input domains and each map
has this law. Transferring enough of that orbit behavior to this fixed reduced
hash is precisely H-cap511. The calculation supplies analytic motivation
and a small margin, not measured full-width evidence or a proof about F.

8. Declared finite probes. Four probes use widths 12 and 16 bits. The two inherited dense
probes retain the following scaled parameters. For a
probe width n, set m_n=2^(n/2), D_n=max(1,m_n/4096), B_n=m_n+D_n. These widths
have D_n=1: every projected state is a checkpoint. Apply the inherited checkpoint
lookup and recovery controller to low_n(F(S||LE32(x))). The probe keeps both
chronological checkpoints and sorted records, and uses exact comparison on the
projected states. It emits distinct predecessor messages or two nulls for each
supplied trial. Organizer hashing independently checks the low-bit XOR-zero
predicate. These are mask collisions, never full 256-bit witnesses. Both the
root implementation and its true complete-message flags match section 2; only
its low word is needed for these projected walks. Memoization is experiment-only
and never a basis for the attack's time or memory bound.

Salt is the supplied 32-byte organizer seed; the projected start is low_n of
SHA-256(b'rho-start'||seed). This deterministic seed expansion supplies repeatable
probes, not independently ideal full-width coins. There is no seed search,
resampling, hidden discarded failure or optional stopping. No observed count is
asserted before trusted execution. The inherited projection widths are retained
before receiving results for the new controller. For these inherited dense probes, D=1
means the probe does not exercise sparse gaps or extrapolate a confidence bound
for the full-width tail or cycle-length condition. Correctness for arbitrary D
is argued in section 5. The full report, whether favorable or unfavorable, is
needed before exploratory qualification; no local host execution is authorized.

Two additional probes, rho12sparse and rho16sparse, use the same widths but
D_n=m_n/16, namely 4 and 16. They exercise nontrivial gaps and local recovery
using the inherited controller, sorted arrays and output predicates. Their spacing
ratio differs from full-width 1/511 and their success frequency is not a
full-width probability estimate. They are declared before any result is seen;
all supplied trials and failures remain included. These probes can expose
sparse-recovery implementation defects that the D=1 probes would miss, without
closing the full-width extrapolation gap. No result is asserted for them.

9. Limits of evidence. Successful 12/16-bit probes can demonstrate finite exact-
target mask events and catch some controller/root defects. They cannot establish
H-cap511, ideal randomness, iid trials or full-width success probability.
Even the additional sparse probes do not test the extremely large spacing
D=2^119. The gap between
those projections and 256-bit walks is enormous, and the random-map margin above
0.39 is small. The heuristic is motivated by the explicit random-map analysis
and the conventional collision-search orbit model, together with whatever finite
evidence the organizer actually produces. No full-width theorem, measured work
at scale, mathematical proof of the heuristic, or rigorous qualification follows
from this package. Unfavorable or inconclusive finite reports must remain visible.

10. Variable-height exact search and work ledger. Let h=bit_length(n) for
n>0. Use a 1024-word key slab at absolute word addresses 0..1023, a terminal
index slab at 1024..2047, and a disjoint J array at 2048..2559. Other objects
are disjoint from these intervals. Internal tree keys occupy 1..2^h-1;
J holds their orbit indices. External leaves occupy 2^h..2^(h+1)-1.
Build internal nodes first. For each external leaf u, find its last-left
ancestor a=u>>(t(u)+1), where t(u) counts trailing one bits. If a=0,
write U at key address u and NONE at index address u+1024. Otherwise
copy K[a] to address u and J[a] to address u+1024. Root and terminal
intervals are disjoint at every h. Old contents outside the active intervals
are ignored. Cache K[1] in a register root_key after every rebuild.

Choose one of ten phase code blocks at each rebuild: empty or height 1..9.
Each block has its own ordinary detection-loop body and fixed-height lookup.
There is no per-query height computation, variable-depth loop or dispatch.
Phase transitions occur only at insertion, charged to fixed rebuild work.
The empty block returns NONE without searching. A nonempty lookup executes:

    b = (root_key < x)
    i = 2 + b

Then h-1 explicit straight-line copies of:

    y = LOAD(i)
    b = (y < x)
    i = i << 1
    i = i + b

Then:

    y = LOAD(i)
    if y != x: return NONE
    k = LOAD(i+1024)
    return k

LOAD is the priced RAM load at the absolute word address. The initial edge
costs two, the remaining edges 4(h-1), the terminal key load one, equality
comparison and branch two, and index addition/load two: total 4h+3.
Return routing is in the nonsearch allowance below. The empty search has no
search work; its routing is in the same allowance. No multiplication, ctz,
conditional move or unpriced address operation is used by a lookup.
Trailing-one decoding occurs only in rebuilds.

Correctness: after descent i is an external leaf. The last-left ancestor is
the inorder lower bound: keys passed by a right edge are <x, and each later
left edge supplies an earlier key >=x. Thus a real exact key, including U,
returns its index; equal padding returns NONE; a greater key fails equality;
the all-right path returns NONE. Internal records and terminal copies are
rebuilt from the same sorted records before querying. Therefore this returns
exactly the same index as fixed-height search for every x and searchable set.
The first edge is identical to initializing i=1, loading K[1], comparing,
shifting and adding the bit, because root_key is K[1]. Consequently the
controller, sufficient event and H-cap511 premise are unchanged.

The search precedes checkpoint insertion. Over the full bounded run n=0
lasts D queries, each n=1..509 lasts D queries, and n=510 lasts 2D queries.
These sum to B=512D. Early termination only reduces work. The height sum is
sum_(n=1)^510 bit_length(n)+9=4088+9=4097. There are 511 nonempty-phase D
intervals. Search work is at most (4*4097+3*511)*D=17921D operations.
The nonsearch controller retains 64 operations per detection call: 12 for
input/output buffers and target setup; 8 for orbit counter/cap/loop routing;
8 for checkpoint tests and j<m; 12 for search return and NONE/hit routing;
8 for pointer/register updates and count access; 16 for literals, addressing
and control transfers. Selecting the phase code is only done at rebuilds.
Recovery retains a separate 128-operation allowance per target call.

Detection costs at most m+D compressions, right reconstruction fewer than D,
synchronous recovery at most 2D, final verification two. Thus every random
choice and failure path obeys
    H <= m+4D+2 =515D+2,
    W <=64*(m+D)+17921D+128*(3D+2)+2^40
       =51073D+256+2^40,
    T <=H+W/638.
With D=2^119=2^128/512, the leading coefficient on 2^128 is
    515/512 + 51073/(512*638).
Its logarithm is 0.21687126813475. The conservative claim 128.217 leaves
more than 2^114 units of slack for all fixed work below 2^31 units.
All failures, verification and recovery are charged. This is total work,
not parallel latency. Compression internals are never discounted.

For fixed work, each insertion shifts at most 511 two-word records, at 32
operations per record plus 512 setup/append operations. Build at most 511
internal nodes using a stack of at most 14 two-word frames, and at most 512
terminal records. Charge 256 operations per node/terminal including traversal,
addressing, tests, stores and trailing-one decoding. Add 4096 per rebuild
for computing height, phase selection, root refresh and transitions. At most
512 rebuilds including initialization cost
    512*(32*511+512+256*511+256*512+4096) <2^32.
The 2^40 fixed allowance covers this plus initialization, two uniform random
word draws, output, verification adapters and finite preliminary research.

11. Memory. C uses 512*32=16384 bytes; sorted records 511*64=32704;
key and terminal-index slabs together 2048*32=65536; J 512*32=16384.
Reserve 65536 bytes for uniform code/constants and 8192 for live words,
compression workspace, buffers and the rebuild stack. Total 204736 bytes,
below 1048576. Each of ten phase bodies can fit in 128 instruction words
including its at-most-39-operation lookup, target call, and the 64-operation
outer controller. These consume at most 1280 words, leaving 768 words for
shared initialization, rebuild and recovery subroutines in the 2048-word code
reserve. Loops in these shared routines bound their code size independently
of data size. No precomputed collision, advice or entire orbit is stored.
Claim memory_log2_bytes=20 conservatively, adding zero normalized penalty.

12. Provenance and limits. This directly builds on the cached-root package
submitted as df041842-52c4-4bdd-9a6d-d81001ea734d, which directly retains
published eb7fbf7c-e57c-407b-a79d-a644516edce1. The full target, salted
injection, cap, H-cap511 premise, sufficient event, recovery and finite probe
source are inherited. The change is only variable-height exact search and
its summed work ledger. Earlier historical provenance includes
f1757b87-5434-43f8-99b5-cff099ef2a14 and salted rho work
6f55e9bf-8eb5-49e5-b37c-0d379ddbe883. Historical names do not assert
verified attribution edges or human decisions. All mathematics needed for
review is included here. The finite probes retain sorted search and do not
execute the new slab layout or validate this RAM instruction count. Their
source is unchanged. Search equivalence is argued in section 10. This is a
conditional generic resource improvement, not new differential cryptanalysis,
full-width empirical evidence or proof of H-cap511. No local host experiment,
rigorous qualification, human acceptance or promotion is asserted.

13. Probe endpoint differences. The inherited probe keeps (start,0) searchable
and inserts endpoint checkpoints even when j>=m. The full attack in section 4
omits searchable zero and indices at least m. Therefore the probes do not
execute exactly the same controller or measure the pruned event. Under E the
first relevant cycle checkpoint is positive and strictly below m, as section 5
proves; removing the other records cannot change that hit. This is a mathematical
equivalence on the sufficient event, not an empirical check of the pruning.
All finite outcomes and failures still require the organizer's report; no source
behavior is presented as an observed full-width success probability.
