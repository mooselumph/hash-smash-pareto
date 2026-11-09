# Sparse-checkpoint salted rho for complete BLAKE3-r3

1. Scope and result. This is a classical ordinary collision construction for
complete unkeyed BLAKE3 with prefix rounds 0,1,2 in every compression. It uses
one explicit fixed-target heuristic H-tail510. Conditional on that premise,
its success probability is at least 0.39. Its deterministic total work is below
2^128.052894327 selected-target compression units, including failures, and all memory
is at most 2^20 bytes. Consequently its normalized time-memory cost is 128.052894327 (section38 controls).
This is a conditional generic construction, not a full-width executed collision,
unconditional security theorem, new differential, or human-accepted result.
The finite probes support only scoped projected walks. Later local execution
is recorded in the public submission note; no full-width observation is asserted.

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
all 256-bit words, using two priced random-word draws. Set N=2^256, D=2^119, m=510*D, and B=m+D=511*D. Execute one bounded attempt. There are no restarts,
parallel processors, advice or retained external precomputation. Counters and
states fit 256-bit words. Let x_i=f_S^i(x0). Store chronological checkpoints at indices aD for 0<=a<=509.
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

5. Deterministic correctness and sufficient event. For a fixed salt and start,
write mu>=0 and lambda>=1 for the tail and cycle lengths. Consider
    E: mu>0, mu<=m-D, mu+lambda<=m.
Set k=ceil(mu/D)*D. Then mu<=k<mu+D and D<=k<=m-D, so this
first positive checkpoint on the cycle is retained. Before its insertion,
every stored checkpoint is on the nonrepeating tail and cannot be revisited.
After its insertion, its first revisit is j=k+lambda. Every later cycle
checkpoint has a later first revisit. Hence no earlier hit preempts this one,
even when the orbit first repeats before checkpoint k was inserted. We have
j=k+lambda<mu+D+lambda<=m+D=B, so detection reaches it before the cap.

The recovery guard passes: j>D and j-D<m. Its retained q checkpoint
reconstructs right=x_(j-D)=x_(k-D+lambda) in fewer than D advances.
The left pointer starts at x_(k-D), strictly before mu. At any comparison
before left reaches mu, that left state is on the unique tail and cannot
agree with a later orbit state. When left reaches mu, the right pointer is
lambda ahead and agrees. This occurs after mu-(k-D) steps, in [1,D].
The saved predecessors are distinct because the left predecessor is on the
tail. Their equal full f_S outputs give two distinct injected messages with
equal complete digests. No lambda>=D condition was needed. In particular,
when lambda<D the right reconstruction starts from q=k-D and takes lambda
steps, and the same synchronous recovery argument applies.
Outside E, every return still checks distinct messages and complete F output,
so no false collision is output. Every failed path remains bounded.

6. Explicit score-critical premise H-tail510. For the fixed complete target F
and exact salted 64-byte injection, over independent uniform full-width S,x0,
posit
    Pr[mu>0 AND mu<=509*2^119 AND mu+lambda<=510*2^119]>=0.39.
This is a hypothesis about actual fixed-target orbits, not reviewer confidence
or a consequence of independent random coins. It differs from the predecessor's
H-cap511: the first-repeat cap is smaller but short cycles are no longer excluded.
No implication between the two fixed-target premises is asserted. The change
has separate ideal-random-map motivation below. The deterministic algorithm
and bounds apply regardless of whether this hypothesis holds.

7. Finite random-mapping supporting calculation. For an independent uniform
map on N=2^256 states, exposing fresh outputs until the first repeat gives
    Pr[mu+lambda<=m]>=1-exp(-m*(m+1)/(2*N)).
The excluded pure-cycle event mu=0 and first repeat by m has probability
at most m/N. For a repeat with mu>m-D and mu+lambda<=m, its first-repeat
transition i lies in (m-D,m], and its prior hit index t lies in (m-D,i).
At most D^2 ordered (i,t) pairs can meet these conditions. Conditional on
no prior repeat, the output at that transition is uniform, so each pair
has probability at most 1/N. The union bound therefore gives at most D^2/N.
Consequently
    Pr[E]>=1-exp(-m*(m+1)/(2*N))-m/N-D^2/N
         >1-exp(-(510/512)^2/2)-2^-18-2^-128
         >0.3910962772 >0.39.
Here m/N<2^-128 and D^2/N=2^-18. This is a finite bound; rounding is
conservative. In a random oracle, salts select disjoint message input domains.
Transfer to the actual fixed three-round BLAKE3 injection remains exactly the
explicit H-tail510 premise. The larger random-map margin is not an empirical
full-width result or proof about reduced BLAKE3.

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
for the full-width tail and first-repeat conditions. Correctness for arbitrary D
is argued in section 5. The full report, whether favorable or unfavorable, is
needed before exploratory qualification; no local host execution is authorized.

Two additional probes, rho12sparse and rho16sparse, use the same widths but
D_n=m_n/16, namely 4 and 16. They exercise nontrivial gaps and local recovery
using the inherited controller, sorted arrays and output predicates. Their spacing
ratio differs from full-width 1/510 and their success frequency is not a
full-width probability estimate. They are declared before any result is seen;
all supplied trials and failures remain included. These probes can expose
sparse-recovery implementation defects that the D=1 probes would miss, without
closing the full-width extrapolation gap. No result is asserted for them.

9. Limits of evidence. Successful 12/16-bit probes can demonstrate finite exact-
target mask events and catch some controller/root defects. They cannot establish
H-tail510, ideal randomness, iid trials or full-width success probability.
Even the additional sparse probes do not test the extremely large spacing
D=2^119. The gap between those projections and 256-bit walks is enormous. The ideal-map
margin does not establish the fixed-target success premise. The heuristic is motivated by the explicit random-map analysis
and the conventional collision-search orbit model, together with whatever finite
evidence the organizer actually produces. No full-width theorem, measured work
at scale, mathematical proof of the heuristic, or rigorous qualification follows
from this package. Unfavorable or inconclusive finite reports must remain visible.

10. Branch-coded variable-height exact search. Let h=bit_length(n) for
n>0. Store internal keys at absolute word addresses 1..2^h-1 in K[0..511],
and their indices at addresses 512+a in J[0..511]. Other objects are disjoint.
Build the perfect tree in inorder from sorted real records followed by
(U,NONE) padding, where U=2^256-1. Cache keys K[1] through K[min(511,2^h-1)] in 511 fixed word registers r1 through r511. These caches are refreshed at every rebuild.

For each possible height h=1..9, use a fixed code fragment for this tree's
geometry, with one block per internal node and one per external leaf.
The geometry and all RAM/code addresses are uniform constants, independent of
salt, state, key values or target outputs. Select this fragment only at rebuild.
Runtime uses a fixed register set x,y,k,r1,...,r511 and the controller registers;
there is no register per tree node and no embedded data-key advice.

The root block compares r1<x and conditionally branches to its right
subtree; otherwise execution falls through into the left subtree. Cost two.
Every non-root node a=2,...,2^h-1 compares its dedicated statically named
register r_a with x and branches, costing two operations. Each fixed code
block names its particular register directly. There is no runtime array or
register-file indexing and no load of a key during traversal. Registers are
priced word-RAM scalar storage; no hardware register-allocation claim is made.
All copies are refreshed by charged literal-address loads on every rebuild.
Lay blocks in preorder. Every external leaf exits to the common MISS/RECOVER
routing, so execution cannot fall through from a finished left subtree to a
right subtree. There is no extra unconditional branch at an internal node.

Each external leaf u has a statically determined last-left ancestor
    a=u>>(t(u)+1),
where t(u) counts trailing one bits in the leaf number. This is calculated
only during uniform code generation, not at query time. If a=0 its block
transfers directly to MISS. Otherwise its block is:

    if r_a != x: goto MISS
    k = LOAD_LITERAL(512+a)
    if k != NONE: goto RECOVER
    goto MISS

The equality comparison/branch costs two. The leaf instruction names r_a
statically, just like the traversal block at node a; its cached value is K[a]. The terminal index
load costs one only on equality. The NONE/hit test and leaf transfers are
in the body9 plus three-operations-per-fetch routing reserve of section15,
never silently omitted.
The empty phase goes directly to MISS. Every nonempty query therefore costs
at most 2h+2 key-search operations, plus a single conditional index
load. No dynamic node indexing, terminal table, multiplication, ctz or
per-query phase dispatch is used. Small addresses are fixed operands in code;
values of keys and indices are read from RAM, not hardcoded or free registers.

Correctness: the selected leaf is exactly that of the former Eytzinger
comparison path. Its last-left ancestor is the inorder lower bound: keys passed
by a right edge are <x and each later left edge supplies an earlier key >=x.
A real exact key including U precedes padding, so equality loads its true index.
Padding loads NONE; greater lower-bound keys fail equality; all-right paths
return NONE. These are exactly the former terminal-table contents, now obtained
by literal-address loads from the original internal arrays. Thus the returned
index on every query. The cap and sufficient event are specified separately
in sections 3-7. No distributional or machine-specific timing premise is added.

The search precedes checkpoint insertion. Over the full bounded run n=0
lasts D queries, each n=1..508 lasts D queries, and n=509 lasts 2D queries.
These sum to B=511D. Early termination only reduces work. The height sum is
sum_(n=1)^509 bit_length(n)+9=4079+9=4088. There are 510 nonempty-phase D
intervals. The key-only search work, through equality comparison/branch, is
(2*4088+2*510)*D=9196D. The saved loads are
D*(sum_(n=1)^509 min(bit_length(n)-1,8)+8)=3578D.
The saved-load sum is sum_(h=1)^8 2^(h-1)*(h-1) + 255*8 =3578:
for heights 1..8 there are 1,2,...,128 phases, and height 9 has
254 ordinary phases plus the doubled final phase, totaling 255.
Height one saves none. This is deterministic, not an average-query estimate. Section 14 proves at most 2D+3 conditional index
loads in the entire run. Thus search work is at most9198D+3. All comparisons and branches remain charged on every query.
Both traversal and terminal keys use explicitly charged scalar storage. Padding matches and
failed recovery are covered by that deterministic bound.
The detection controller uses at most 9 nonsearch operations per call, plus three per
conditional index fetch,
explicitly implemented as in section 15. Its countdown moves cap and insertion
decisions to at most 510 phase boundaries. Constants and phase body are
selected at initialization/rebuild only.
Recovery retains a separate 128-operation allowance per target call.

Detection costs at most m+D compressions, right reconstruction fewer than D,
synchronous recovery at most 2D, final verification two. Thus every random
choice and failure path obeys
    H <= m+4D+2 =514D+2,
    W <=9*(m+D)+9198D+3+3*(2D+3)+128*(3D+2)+2^40
       =14187D+268+2^40,
    T <=H+W/638.
With D=2^119=2^128/512, the leading coefficient on 2^128 is
    514/512 + 14187/(512*638).
Its logarithm is 0.0667260888485. The conservative claim 128.067 leaves
more than 2^108 units of slack for all fixed work below 2^31 units.
All failures, verification and recovery are charged. This is total work,
not parallel latency. Compression internals are never discounted.

For fixed work, each insertion shifts at most 511 two-word records, at 32
operations per record plus 512 setup/append operations. Build at most 511
internal nodes using a stack of at most 14 two-word frames. Charge 256
operations per node including traversal, addressing, tests and stores. Retain
an additional512*256 operations per rebuild for routing/bookkeeping, even
though static leaf-ancestor decoding is generated once and no terminal table
is built. This conservative overreserve requires no additional retained array. Add 4096 per rebuild
for computing height, phase selection, root refresh and transitions. At most
512 rebuilds including initialization cost
    512*(32*511+512+256*511+256*512+4096) <2^32.
The 2^40 fixed allowance covers this plus initialization, two uniform random
word draws, output, verification adapters and finite preliminary research.

11. Code and memory. C uses512*32=16384 bytes; sorted records511*64=32704;
K and J together1024*32=32768. Reserve32768 for live words, buffers, compression
workspace and rebuild stack, and655360 bytes for uniform code/constants.
Total769984 bytes, below1048576. Claim memory_log2_bytes=20 conservatively,
so normalized time-memory cost equals the raw time exponent.

Across h=1..9 there are sum(2^h-1)=1013 internal node blocks and
sum(2^h)=1022 external leaf blocks. Nine root blocks cost two instructions;
the other1004 nodes cost three each, total3030. At most eight instructions
per leaf includes key load, equality comparison/branch, index load, NONE
comparison/branch, common-continuation transfer and one spare:8176 more.
Reserve4096 additional instruction words/constants for all shared initialization,
phase control, insertion, rebuild, adapter and recovery routines. Total15302
words is below the20480-word code reservation. Encode each instruction in
one32-byte word: opcodes, fixed register IDs and small literal addresses all
fit comfortably. All RAM/code addresses are below2^16 words. Full-width U/NONE
and other constants occupy the included pool/registers initialized once, not
oversized instruction immediates. Uniform code generation uses loops and fixed
geometry only, charged under2^40 fixed work; no target search is hidden in code.
The live scalar set includes 511 cached keys, charged as 16352 bytes in
the 32768-byte workspace. Reserve a separate 1024 bytes there for descriptors
and controller, leaving 15392 bytes for target workspace, buffers and rebuild
stack. These are scalar storage in the priced RAM model, not 511 free hardware
registers. Instructions explicitly name a scalar; there is no computed lookup.

12. Provenance and limits. This directly builds on submission
74ded014-50b9-4f96-abfb-efc8146ff5f2. Its complete target, sparse checkpoints,
recovery, phase countdown, descriptor, equality-fetch
bound and four experiment sources are retained. The predecessor expanded the cache from 31 to all 511 possible keys.
This revision reuses those same caches at statically known terminal leaves. Each r_a is refreshed to K[a] at a rebuild;
no lookup modifies either copy, so every comparison result is identical on
every orbit. Terminal equality now directly names the same fixed cache register,
saving one load per nonempty query; it still performs the equality comparison
and branch and retains the conditional index load. This proves lookup equivalence independently of any distributional premise.
The new cap and sufficient event are separately specified in sections 3-7. No older source was separately used. Publication
and pending AI validity do not imply human acceptance or verified attribution.
No new differential or full-width evidence is claimed.

13. Probe endpoint differences. The inherited probe keeps (start,0) searchable
and inserts endpoint checkpoints even when j>=m. The full attack in section 4
omits searchable zero and indices at least m. Therefore the probes do not
execute exactly the same controller or measure the pruned event. Under E the
first relevant cycle checkpoint is positive and strictly below m, as section 5
proves; removing the other records cannot change that hit. This is a mathematical
equivalence on the sufficient event, not an empirical check of the pruning.
All finite outcomes and failures still require the organizer's report; no source
behavior is presented as an observed full-width success probability.

14. Equality-only terminal fetch bound. The program in section 10
returns NONE before the terminal-index fetch when its cached lower-bound key differs
from x. Only the conditional index load, one operation, is skipped; its RAM address is a literal in code.
For x!=U, equality must be a real record: every padding key is U. Its index
is positive, so it immediately enters RECOVER. Every RECOVER path, including
guard rejection or failed verification, terminates the attempt. Hence at most
one non-U equality fetch occurs in the entire detection run. The empty phase
performs no terminal fetch.

It remains to bound U-state queries, allowing a padding-U key to return NONE
repeatedly. Let the actual orbit's tail and cycle lengths be mu and lambda;
no distributional assumption is used. If U is a tail state, it occurs at most
once. If U is a cycle state, let k be the first positive checkpoint index
on that cycle: k=D*ceil(max(mu,1)/D). Thus mu<=k<=mu+D.

If k<m, it is inserted unless detection has already terminated. Its first
revisit is at k+lambda. Exact lookup therefore stops detection no later than
that index, whether recovery succeeds or fails. If this revisit exceeds the
cap B, the cap stops detection earlier, so the same upper bound still holds.
All cyclic U occurrences are in the interval [mu,k+lambda], of length at most
D+lambda, spaced exactly lambda apart. Their number is at most
floor(D/lambda)+2<=D+2. This also covers pure cycles mu=0, for which k=D.
If k>=m, since m=510D is an integer multiple of D and D<m, we have mu>m-D.
All cycle-state queries then lie in an interval of length less than
B-(m-D)=2D. There are at most 2D+1 U-state queries. Combining all cases,
2D+2 is a conservative uniform bound on U-state queries in detection.

Each such query needs at most one equality fetch, and there is at most one
non-U terminating fetch. Thus the fetch count is at most 2D+3 on every orbit,
not merely on E or typical random mappings. The resulting search bound is
9198D+3, yielding the ledger in section 10. The inherited branch-coded lookup supplies the same indices, with the same success
event and heuristic. No finite probe is changed. The tighter time exponent
128.0667260888485 is conservatively rounded to 128.067; the positive slack
exceeds 2^108 target units and covers fixed work below 2^31. This is deterministic
accounting, not a claim that key matches are probabilistically rare.

15. Phase-countdown detection controller and persistent adapter. This revision
uses an at-most-9 nonsearch body, plus at most three additional
routing operations for each conditional index fetch. There is one lookup code fragment for each height 0 through 9,
as in section 10, and one common phase-boundary routine. At initialization set
j=0, n=0 and remaining=D. Here n counts searchable checkpoints. After each
insertion n increases by one. While n<509 the next phase has length D; after
inserting checkpoint 509D the final phase has length 2D. A lookup hit jumps
directly to terminal RECOVER. Every lookup miss, including a padding index NONE,
jumps to the MISS block replicated for that height. Lookup's key comparisons, branches and
conditional index loads are charged in section 10, with additional routing
charged below. No stale k is tested on a mismatch path.

    LOOP_FOR_CURRENT_HEIGHT:
        target_adapter()              # 4 operations plus one compression
        j = j + 1                     # 1 addition
        inline_phase_lookup(x)        # section 10; miss routes to MISS
    MISS_FOR_CURRENT_HEIGHT:
        remaining = remaining - 1     # 1 subtraction
        if remaining != 0: goto LOOP_FOR_CURRENT_HEIGHT  # compare + branch: 2
        goto BOUNDARY                 # charged even though at most 511 times
    BOUNDARY:
        if n == 509: return FAILURE
        append x to C; sorted_insert(x,j); rebuild_lookup()
        n = n + 1
        remaining = (2*D if n == 509 else D)
        goto LOOP_FOR_SELECTED_HEIGHT

The boundary routine, its comparisons, branches, assignment and transfer are
charged a generous 4096 additional operations per boundary under fixed work.
There are 509 insertion boundaries and one final boundary, never an unbounded
loop. There is no per-query j==B comparison, j&(D-1), or j>=m comparison.
The loops and branch destinations depend only on public constants and the
current height. They require no data-dependent code generation.

An induction gives the precise semantic equivalence with section 4. The initial
empty phase processes queries 1 through D before inserting checkpoint D.
For n=1 through 508, phase n processes nD+1 through (n+1)D before inserting
checkpoint (n+1)D. Phase n=509 processes 509D+1 through 511D and fails at
511D after the last lookup. Thus every query and every insertion of section 4
occurs in exactly the same order. In particular there is no insertion at 510D,
no insertion after the cap, and no cap failure before its lookup. A hit bypasses
MISS and enters recovery with the same j,k and chronological array; remaining
is unused in the terminal recovery. Early termination can only decrease work.
The full state sequence, hit index, failure/success result and event E are
therefore identical on every salt and start, without any distributional premise.

Per ordinary detection query charge adapter4, j increment1, remaining
decrement1, remaining comparison plus conditional branch2, and one routing
transfer, total9. This covers empty-phase and all-right leaf transfers to MISS.
For ordinary mismatch leaves, the equality comparison/branch already counted
in search jumps directly to MISS; no extra transfer is needed. The loop branch
already targets the fixed current-height body, with no runtime dispatch.

Only a terminal equality path performs the index load. After it, reserve three
additional routing operations: NONE comparison, conditional branch, and transfer
to MISS or RECOVER. Section14 bounds all such paths by 2D+3, independent of
orbit distribution. These extra operations therefore cost at most6D+9, rather
than a per-query allowance. Hit paths bypass remaining updates but are still
bounded by the same generous body9 plus this reserve. Transfers at boundaries
are counted in the separate fixed-work reserve. No failed path or padding match
escapes either reserve. The key-equality comparison/branch and index load remain
separately charged in search. Recovery has its own128-operation allowance.

The inherited adapter uses a persistent read-only descriptor: message pointer,
standard IV pointer, counter zero, true length 64, flags 11, rounds 3 and output
pointer, initialized once. Salt S occupies the first 256-bit message word. Each
call stores x to the second message word (1), transfers to the complete selected
compression (1), returns (1), and loads all first 256 output bits into x (1).
The full compression is separately charged as H=1, without discounting invariant
arguments. Its private workspace is disjoint from the descriptor and orbit and
lookup registers. Little-endian message/output word representation is exactly
section 2; no host ABI, nonstandard root, extra message copy or free-start IV
is used. Detection is never resumed after recovery. The eight-word descriptor
and remaining/n registers fit in the expanded 32768-byte workspace.

The common boundary routine needs fewer than 128 extra code words. The ten
height-specific MISS blocks require at most six instructions each, below 64. Removed old per-query tests free code space;
even charging all 192 as additional words uses 15494 words below the existing
20480-word code reservation. No duplicate tree per phase is stored. All code
and workspace remain below the reported one-MiB bound. Additional boundary
work is at most 511*4096 <2^21, absorbed by the existing 2^40 fixed reserve.

Combining body9, equality routing, key search and recovery gives
    H <=514D+2,
    W <=9*511D+9198D+3+3*(2D+3)+128*(3D+2)+2^40
      =14187D+268+2^40,
    T <=H+W/638.
The leading exponent is 119+log2(514+14187/638)=128.0667260888485.
The submitted bound 128.067 has more than 2^108 target units of rounding
slack, exceeding 2+268/638+2^40/638. It covers all fixed costs and failed paths.
This retains the countdown controller and all 511 cached keys,
improving the predecessor submitted bound 128.083. The finite probe sources are unchanged. The new fixed-target premise is
explicitly distinct from H-cap511; no logical strengthening claim is made.

16. Cache refresh work and code. At every rebuild refresh each real internal
node's fixed scalar cache, including padding keys, using at most 511 loads.
There are at most 512 rebuilds. The extra 480 loads per rebuild relative to
the predecessor total at most 245760 fixed operations, covered by 2^40.
Use a statically unrolled refresh routine of at most 1024 instruction words.
The previous code ledger was 15750 words. Even without credit for removed
traversal loads, 15750+1024=16774 is below the enlarged 20480-word reservation.
All instructions and constants use the same 32-byte encoding, with explicit
register IDs large enough for 511 caches. No target-derived code is generated.
The workspace increase from 8192 to 32768 and code increase from 524288 to
655360 are fully charged. Total storage is
16384+32704+32768+32768+655360=769984 bytes, less than one MiB.

17. Revision check. The predecessor cached all 511 possible internal keys but
still loaded the terminal equality key from K[a]. For any external leaf the
ancestor index a is a uniform code-generation constant. Its terminal block
can compare r_a directly with x. The equality result is identical because
r_a=K[a] until the next rebuild. Padding and U are unchanged; the conditional
index fetch and its bound remain exactly section 14. There are 510D nonempty
queries in the full capped detection run. This removes exactly 510D primitive
loads from its worst-case search ledger, independently of query distribution.
The key-only work is (2*4088+2*510)D=9196D; adding at most 2D+3 index fetches
gives 9198D+3. No extra register, refresh, code block or retained object is
needed. Each terminal block only shrinks by one instruction, so the existing
769984-byte memory and code reservation remain valid. The total ledger is
    H <=514D+2,
    W <=14187D+268+2^40,
    T <=514D+2+(14187D+268+2^40)/638.
Its leading exponent is 128.0667260888485. Rounding up to 128.067 leaves
more than 2^116 target units of slack, exceeding all fixed work. The change
is exact and deterministic; All experiment programs, rounds and message domain are unchanged.
The success event and premise are revised explicitly in sections 5-7; the
first-repeat cap falls from 511D to 510D, reducing detection by D. The immediate predecessor claimed
128.083, with qualification and human review statuses to be checked separately.

18. Controller reserve refinement. The immediate predecessor reserved14
nonsearch operations on every detection query, including transfers only taken
on equality paths. Here the common body is explicitly9 and those equality
transfers are individually reserved at most3*(2D+3), using the existing exact
fetch bound. This reduces the ledger by (5*511-6)D-9 primitive operations
relative to applying body14 at the new cap. No success event, target, experiment
or memory change is involved. The final unconditional ledger is
    H<=514D+2,
    W<=14187D+268+2^40,
    T<=514D+2+(14187D+268+2^40)/638.
The leading exponent128.0667260888485 is rounded upward to128.067. All fixed
terms remain far smaller than the rounding slack. This combines exact terminal
cache reuse, the explicitly revised sufficient event/cap, and routing accounting.

19. Current revision: implicit detection index and fallthrough miss. This section
supersedes sections 10, 15, 17 and 18 wherever they retain the old body9 ledger
or per-query index increment. All target, event, checkpoint, lookup and recovery
semantics in sections 2-9 and the fixed-target premise H-tail510 are unchanged.
The direct source is submission 406293fb-52fb-4025-a627-9a8667f0973c, whose
submitted bound was 128.067 and whose human review was pending when inspected.

Maintain phase_start and phase_length as fixed scalar words. Initially these
are 0 and D. After inserting checkpoint nD, set phase_start=nD, and set
phase_length=D for n<509, otherwise 2D. These assignments occur only at the
at-most-510 boundaries and are charged to the fixed reserve. remaining is
initialized to phase_length at each phase. Do not increment j on each query.
On a hit, before recovery, compute
    j = phase_start + phase_length - remaining + 1.
The hit bypasses the MISS decrement, so this is the precise current query index.
At a boundary, remaining has become zero; the insertion index is exactly
phase_start+phase_length. No target query needs j as an input. Insertion,
chronological recovery, hit guards and the cap therefore see exactly the
same integer indices as before. Induction on queries within each phase proves
remaining=phase_length-t+1 before the t-th query's MISS decrement. There is no
rounding, division or probabilistic assumption in this transformation.
All three arithmetic operations for hit-index reconstruction and its transfers
are absorbed in the fixed reserve; reconstruction occurs at most once because
recovery always terminates the attempt. Boundary indexing uses constant shifts
and additions and is covered by the existing 4096-per-boundary reserve.

Place the unique all-right external leaf of each height directly before that
height's MISS block. It falls through into MISS with no instruction. Preorder
node layout already ends at this leaf. Every other nonmatching leaf uses the
previously charged equality comparison and conditional branch directly to MISS.
Equality paths retain their three-operation NONE/hit routing reserve. For the
empty height, place the target adapter immediately before MISS. Its return is
already charged to the adapter. No unconditional transfer on an ordinary miss
is required. The loop's conditional branch still targets its height-specific
adapter and is charged. Boundary transfers remain in fixed work, not silently
omitted. Internal node branches and all key comparisons are unchanged.

The per-query nonsearch body is now adapter4, remaining decrement1, remaining
comparison1 and conditional branch1, total7. There is no j increment or extra
miss transfer. A boundary-only goto BOUNDARY, if needed, executes at most510
times and is separately charged to fixed work. Hit queries are conservatively
charged body7 even though they bypass remaining updates. Every other query,
including padding-U matches returning NONE, is charged the appropriate equality
routing plus body7. The deterministic fetch bound 2D+3 still applies.

Consequently the new unconditional ledger is
    H <= 514D+2,
    W <= 7*511D + 9198D+3 + 3*(2D+3) +128*(3D+2)+2^40
       =13165D+268+2^40,
    T <= 514D+2+(13165D+268+2^40)/638.
The leading exponent is 119+log2(514+13165/638), less than128.063.
The 128.063 submitted bound rounds upward with enormous slack over
2+268/638+2^40/638. No compression, unsuccessful path, memory operation or
randomness is discarded. At most two extra live scalar words and fewer than
64 extra instruction words fit the existing 32768-byte workspace and
20480-word code reservation. Reserved total memory remains769984 bytes,
below one MiB. The old ledgers are historical derivations; this section alone
sets the final bound. All experiment sources and manifests are byte-identical
to the direct predecessor. The same finite evidence limitations apply.

20. Current final ledger: concrete bounded recovery. This section supersedes
section19's inherited recovery allowance and final time bound; its implicit
index and fallthrough controller are retained exactly. There is no change to
H-tail510, the success event, full target, lookup, probe source or memory bound.
The immediate research predecessor is fd72c834-7259-42bf-8e4e-428509aae9d9,
which introduced section19 and submitted128.063. At drafting its remote
validation was pending. Its underlying direct source406293fb-52fb-4025-a627-9a8667f0973c
supplied the construction and unchanged experiments.

Use the persistent target adapter of section15 for every recovery call.
Conservatively charge every scalar assignment a source load and destination
store, even if registers could permit a cheaper move. The guarded recovery
initialization computes q, loads left and right, and initializes a loop counter
once. This finite work, hit-index reconstruction and all guard failures fit
under the existing2^40 fixed reserve, separately from the per-call charges.

The right-alignment loop executes at most D-1 times. Copy right to x (2),
execute adapter (4 plus one complete compression), copy x to right (2),
increment the loop counter (1), compare it to the fixed bound (1), and branch
back if needed (1). This is11 ordinary operations per target compression.
Loop entry and its possible empty-loop test occur once and are fixed work.

For each synchronous recovery iteration use this literal order:
    a=left; b=right
    x=left; target_adapter(); left=x
    x=right; target_adapter(); right=x
    if left==right: goto VERIFY
    h=h+1
    if h<=D: goto SYNCHRONOUS
    return FAILURE
Initialize h=1 before entry. The two saved predecessor assignments cost4.
Each pointer update costs8: two copies at2 each and adapter4. Equality test
and its branch cost2. Counter update, bound comparison and branch cost3.
Total25 ordinary operations for two complete compressions, on every failed
comparison. A hit bypasses counter work and costs no more. The exhausted-loop
failure transfer occurs once. Even adding two explicit control transfers per
iteration would cost27, still below64, the proposed32-per-compression reserve.
At most D iterations execute. Loop entry guards, all terminal failure transfers
and the initial left==right test are charged to fixed work.

VERIFY executes at most once and terminates. Distinct predecessor testing,
message construction, two complete target recomputations, full-output equality
and return handling need fewer than128 ordinary operations, charged to fixed
work. Its two compressions are still charged in H. No failing verification is
retried. The2^40 global allowance covers the former rebuilding bound below2^32,
all initialization, code generation and these bounded terminal routines with
more than two orders of magnitude of remaining margin. Reducing a per-call
reserve does not remove those independent fixed charges.

Consequently the recovery allowance32*(3D+2), rather than128*(3D+2), bounds
all repeated recovery ordinary work. It is conservative for both loops above.
Using unchanged body7, exact search and equality routing gives
    H<=514D+2,
    W<=7*511D+9198D+3+3*(2D+3)+32*(3D+2)+2^40
      =12877D+76+2^40,
    T<=514D+2+(12877D+76+2^40)/638.
The leading exponent119+log2(514+12877/638) is128.0611912950735.
The submitted bound128.0613 rounds upward and covers every fixed term, since
its positive gap is larger than2^110 target units whereas the fixed terms
are below2^31. Total memory remains769984 bytes and the claim conservatively
reports20. At most64 extra recovery code words fit the existing code reserve.
This is an exact concrete controller refinement; no faster hardware, average
runtime, ideal-map timing or strengthened probability premise is assumed.

21. Additional finite pruned-controller evidence. New rho12pruned and
rho16pruned probes retain the inherited complete root computation, deterministic
seed scheme and m=2^(n/2), D=m/16 at widths12 and16. They omit searchable
(start,0), insert only positive checkpoints below m, and reject q>=m before
chronological recovery. They therefore address the endpoint-controller gap in
section13 for these finite widths. All inherited experiments are retained
unchanged, including all unfavorable outcomes. New probes were specified before
observing their new reports; there is no seed search, stopping rule or trial
selection. The organizer independently recomputes every emitted pair's mask
event and distinctness. Failed trials emit null pairs. This is still projected
walk evidence, not an implementation of the full-width code-generated lookup,
a proof of H-tail510, measured cost, or an iid confidence interval. The spacing
ratio1/16 still differs from1/510; no full-width extrapolation is newly asserted.
The new source is a separate direct regular Python file derived from the same
predecessor's rho_probe.py with the endpoint changes just listed. All participant
code is reserved for the organizer isolated executor; no host execution occurs.
Any result below or above the ideal-map expectation must remain visible.
The final score and deterministic bounds remain exactly section20.

22. Final asymmetric recovery ledger. This section supersedes section20's
uniform recovery reserve and final score, retaining its literal controller.
The direct material source is 56f78fef-14ac-40ac-ab8c-c9a31a4b189f.
There is no new probability premise, target, lookup or experiment change.
Right alignment has at most D-1 iterations, at 11 ordinary operations each.
The synchronous loop has at most D iterations, at 25 ordinary operations each
for its TWO compressions, as individually enumerated in section20. To retain
explicit extra control-transfer slack, charge 27 per synchronous iteration.
Thus repeated recovery work is at most 11(D-1)+27D <=38D, rather than
32*(3D+2). Every assignment, failed comparison and loop back edge is included.
Initial guards, empty-loop tests and all terminal handling occur at most once
and remain in the independent 2^40 fixed allowance. The two verification
compressions remain in H. No failed trial or verification is omitted.

The final unconditional bounds on every salt/start are therefore
    H <=514D+2,
    W <=7*511D+9198D+3+3*(2D+3)+38D+2^40
      =12819D+12+2^40,
    T <=514D+2+(12819D+12+2^40)/638.
Here D=2^119, C=638. The leading exponent is less than128.060947.
The submitted bound128.0610 rounds upward; its gap exceeds2^110 target
units and covers fixed terms less than2^31. Code, workspace and experiments
are unchanged, total memory remains769984 bytes and reported exponent20.
No assumption about random runtime, favorable recovery length or distribution
has entered this refinement. The sufficient event E and H-tail510 remain
exactly the source's conditional success argument. This is an accounting
improvement of that explicit algorithm, not a new cryptanalytic differential.

23. Exact synchronous-loop charge. This revision builds directly on submission
0c642354-3755-4a65-a4e0-8e0db4ddc1f5. Section22 reserves27 operations per
synchronous iteration although section20 explicitly counts25. Use exactly the
literal order in section20, with its conditional back edge and VERIFY exit.
The two predecessor saves cost4; the two pointer updates cost16 including
both adapters; equality comparison and conditional branch cost2; counter
increment, bound comparison and conditional back edge cost3. Total25.
The equality branch directly targets VERIFY; the back edge directly targets
the first predecessor save. Neither needs an extra intermediate transfer.
The final fallthrough failure and initial loop entry each occur once, charged
in the existing2^40 fixed reserve. This bound covers successful and failed
iterations independently of orbit statistics. Alignment remains11 per step.
Thus repeated recovery ordinary work is at most11(D-1)+25D<=36D.
The two complete compressions per synchronous step remain fully charged.

The final unconditional ledger replacing section22 is
    H<=514D+2,
    W<=7*511D+9198D+3+3*(2D+3)+36D+2^40
      =12817D+12+2^40,
    T<=514D+2+(12817D+12+2^40)/638.
Here D=2^119. The leading exponent is below128.060938; the submitted
128.06094 rounds upward with ample slack for the fixed terms below2^31.
The exact target, success event, explicit H-tail510 premise, six experiments,
finite-evidence limitations and769984-byte reservation are unchanged.
No extra code is required: two reserved control transfers have been removed
from an allowance, and the existing concrete controller is used literally.
This is an accounting refinement, not a new full-width collision or theorem.

24. Padding-aware leaf specialization. This section is the final controlling
revision, superseding section23's lookup fetch/routing bound and submitted time.
The direct material source is27988b01-25be-4c2b-ae7b-93e8aad87cad.
It retains spacing D=2^119, m=510D, B=511D, the exact target adapter,
all checkpoint capacities, phase controller and recovery, and H-tail510 verbatim.
It does not use the denser parameters or inline target of the rejected later
submission. All six finite experiments remain unchanged with their limitations.

The previous code's last-left ancestor a at each external leaf is determined
only by the perfect-tree geometry. Its inorder rank is similarly a geometry
constant. At every boundary rebuild, specialize the terminal code in the current
height fragment according to n, the number of actual searchable records. Use
fixed-size six-word terminal slots, so node branch addresses never change.
For a=0 retain the all-right fallthrough into MISS. If a is a padding node
(inorder rank greater than n), set the first instruction in the leaf's slot to
an unconditional jump to MISS; the remaining words are unreachable. If a is
real, emit the following instructions in its slot:
    compare r_a with x
    branch to MISS if unequal
    k = LOAD_LITERAL(512+a)
    jump to RECOVER
The remaining two slot words are unreachable. RECOVER includes the one-time
hit-index reconstruction of section19. Its guards and verification terminate
the attempt on every outcome, including failure. This terminal path has no
NONE comparison: every real record's index is positive and less than m.

This is uniform finite code construction from public n, not target-derived
advice. At most512 leaves are patched at each of at most512 rebuilds. The
inorder layout traversal already identifies which nodes contain real records.
A depth-first traversal with at most10 two-word stack frames computes each
leaf's last-left ancestor and its rank, then emits its literal instructions.
Reserve1024 primitive operations per node or leaf for stack updates, comparisons,
address arithmetic, rank propagation and emitting at most6 instruction words.
With fewer than1024 geometry blocks per rebuild and at most512 rebuilds,
this additional work is below2^29 operations. The existing fixed allowance2^40
covers it in addition to the inherited setup/rebuilding bounds. Rewriting is
completed only at boundaries; the program is never changed during a phase.
All instruction fetches and branch operands have the same RAM interpretation
as the inherited uniformly generated branch-coded trees. No native executable
memory assumption or hardware register-allocation benefit is claimed.

Correctness on EVERY query: the tree comparisons reach the same external leaf
as before. If the lower-bound ancestor is real, its cached key is unchanged
and exact equality returns its same positive index. If it is padding, its key
is U. In inorder every real key is before every padding key, including a real U.
For any x<=U, if any real key is >=x, the lower bound is that real key, so a
padding lower bound implies no real key equals x. Therefore padding may return
MISS immediately, including when x=U. When a real U is present its earlier
inorder position makes it the lower bound and the real terminal block detects
it. The all-right leaf has no lower bound and remains a miss. Thus no true hit
is removed and no false hit is introduced. The orbit, checkpoints, detection
index and outcome remain identical to the predecessor for every salt/start.
The sufficient event and its explicitly conditional probability are unchanged.

A padding leaf now costs1 operation instead of the old equality comparison
and branch2, so retaining the old2-per-nonempty-query key terminal allowance
is conservative. Real terminals retain that allowance. Internal comparisons
are unchanged. Thus key search still costs at most9196D operations. There is
now at most ONE conditional index load across the entire run: only a real
match can reach it and that match jumps immediately to terminal recovery.
Its jump costs one additional operation. Charge both in fixed work, with an
explicit extra2 outside the reserve. There are no padding NONE index loads,
no repeated NONE comparisons and no recurring equality routing. Every ordinary
query still pays the full section19 body7; this includes adapter, remaining
update and loop comparison/branch. A hit bypassing countdown is overcharged.
Alignment and synchronous recovery remain36D ordinary operations. Hence
    H <=514D+2,
    W <=7*511D+9196D+36D+2+2^40 =12809D+2+2^40,
    T <=514D+2+(12809D+2+2^40)/638.
The leading exponent is128.0609034122678. Submit128.060904, rounded upward;
its slack exceeds2^107 target units, while fixed terms are below2^31.
This is a deterministic total-work bound over all coins, including failures.

Memory: retain the same arrays,511 key-cache scalars and32768-byte workspace.
All heights1..9 have total1013 internal nodes and1022 external leaves.
Their node blocks use2026 instruction words, and six-word leaf slots use at
most6132 words. The all-right fallthrough does not need its slot, but retain
this upper bound. Their total8158 words is below the old code reservation
20480 words. Reserve an additional2048 words specifically for the leaf-patching
traversal and rank computations. Even adding these to the inherited16774-word
code ledger (section16, rather than claiming all its savings), then192 words
for phase bodies and64 words for recovery, totals19078 words, below20480.
Fixed-size terminal slots never exceed the old six-instruction bound per leaf:
comparison/branch2, index load1, NONE comparison/branch2, miss transfer1.
Thus the added2048-word patch routine fits without enlarging the existing
655360-byte code allocation. The inherited32768 workspace has room for the
640-byte traversal stack; allocate it within the existing rebuild scratch,
reusing the stack after tree construction, never overlapping live cache words.
Total reserved storage remains769984 bytes, including code and working state,
conservatively reported as2^20 bytes. Normalized time-memory cost equals raw
time. No experiment source is evidence of running the patched full-width
lookup: its correctness and cost are analytic obligations addressed here.

25. Paired-query countdown (current controlling revision). This revision builds
on 6edcfe7f-92ac-4501-b6f7-a219723114b5. It retains the exact target, D=2^119,
m=510D, cap511D, H-tail510, all six experiments, padding-aware lookup and
recovery. Only detection loop control changes. Earlier final ledgers are
historical; this section controls the submitted bound.

For each height make two copies A and B of its lookup fragment, including
section24's fixed terminal slots. Both copies name the SAME cached key scalars
and literal index array addresses. Internal branch destinations stay within
the respective copy. Mismatch branches in A target adapter B; mismatches in B
target COUNT. Place each all-right leaf directly before its corresponding
continuation, so it falls through without an instruction. Real terminal hits
jump to HIT_A or HIT_B respectively. Padding leaves retain their charged
unconditional jump, now to the same respective continuation. The empty-height
case simply has adapter A followed by adapter B then COUNT.

At a boundary initialize remaining=phase_length exactly as section19. Execute:
    A: target_adapter(); inline_lookup_A(x)
    B: target_adapter(); inline_lookup_B(x)
    COUNT: remaining=remaining-2
           compare remaining with zero
           branch to A if nonzero
           goto BOUNDARY
Both phase lengths D and2D are even. remaining before A is therefore a positive
even number. No query crosses a boundary or cap. At a hit reconstruct
    HIT_A: j=phase_start+phase_length-remaining+1; goto RECOVER
    HIT_B: j=phase_start+phase_length-remaining+2; goto RECOVER
The selected hit stub uses a fixed literal offset. There is no per-query lane
variable, runtime code dispatch, indirect continuation or new adapter cost.
The target adapter and all complete compression charges are unchanged.

By induction each pair queries the next two orbit states, with exactly the
same lookup and chronological checkpoint contents as section24. A hit in A
terminates before B. A hit in B has the second current index. If both miss,
COUNT consumes exactly two queries; zero triggers the identical boundary.
Thus the state sequence, first hit, every failure and recovery result are
identical for every salt/start. This is deterministic equivalence, without
any new orbit or timing heuristic. In particular the sufficient success event
and conditional probability0.39 are unchanged.

There are at most511D detection queries and at most511D/2 countdown executions.
Adapter work is4 per query. Each countdown costs subtraction1, comparison1,
conditional branch1. Boundary transfers remain fixed work. Early hits skip
COUNT; they cannot increase either bound. Hence detection nonsearch work is
at most (4*511+3*511/2)D=2810.5D instead of3577D. Search still costs9196D;
copying changes no traversal or terminal operation. The single terminating
index load and its transfer still cost2 fixed operations. Recovery costs36D.
Consequently the unconditional ledger over all coins, including failures, is
    H<=514D+2,
    W<=12042.5D+2+2^40,
    T<=514D+2+(12042.5D+2+2^40)/638.
The leading exponent is128.05765440084906. Submit128.057655, rounded upward.
The slack exceeds2^107 compression units; fixed terms are below2^31.
No full compression or unsuccessful search work has been discounted.

Memory and construction work: the prior19078-word conservative code ledger
includes all old lookup fragments, patch generation, phase and recovery code.
One additional full lookup copy costs at most8158 words (2026 internal-node
instruction words plus6132 terminal-slot words across heights1..9). Reserve
another256 words for duplicated adapters, COUNT blocks and hit stubs for all
ten heights, in addition to every old control block, even if unreachable.
Total code bound is27492 words, or879744 bytes at32 bytes per instruction.
Keep all previous noncode allocations:16384+32704+32768+32768=114624 bytes.
Total994368 bytes is below1048576. Code and working memory are both charged;
there is no reliance on free hardware instruction caches or free registers.
Report memory_log2_bytes=20 conservatively. The enlarged code addresses remain
below2^16 words. A single instruction can still encode each small address and
register identifier with its opcode in256 bits.

At rebuilding, patch both terminal copies with their respective continuations.
At most twice the section24 traversal/emission work is required, plus linear
copy/branch relocation for8158 instructions. Reserve fewer than2^31 additional
primitive operations across all512 boundaries: even4096 operations per copied
instruction at every boundary would be excessive; concrete copying uses at
most32 per instruction for load/store, offset addition, opcode classification,
comparison/branch and loop control, giving8158*512*32<2^28. Duplicated terminal
patching adds less than2^29. The existing2^40 allowance covers these alongside
all prior setup/rebuilding charges below2^32. No target search or output-derived
advice is performed by generation. The live traversal stack reuses prior scratch.
No experiment source changes. The probes test finite projected controllers,
not this generated paired layout, full-width probability, or this cost bound.
This revision's evidence for the loop transformation is the induction and
instruction/memory ledger above; inherited evidence limitations remain explicit.

26. Four-query reusable geometry arena (current controlling revision).
This builds directly on a76336a7-eb93-4a24-85c5-a6ff83fb2e6e and replaces
section25's two-query control and all-height code storage. All target, orbit,
checkpoint, recovery, success event, fixed-target heuristic, and six experiment
sources remain unchanged. The revised bound is128.056028 at memory exponent20.

Only ONE height is active between checkpoint rebuilds. Accordingly allocate a
reusable arena with FOUR lookup slots, each large enough for the largest tree
h=9. Do not retain any inactive-height lookup instruction templates or old
lookup copies in code memory. Generate the active height directly from geometry
at each boundary while executing the generator in separate persistent code,
outside the arena. The generator emits absolute branches within each slot
and fixed branches to the appropriate continuation/hit stub. No active lookup
executes during generation. Key caches and index arrays remain disjoint and
unchanged. This is an abstract charged word-RAM code layout, as before, with
no new native-code execution assumption or uncharged instruction storage.

One h<=9 fragment has at most511 internal nodes and512 external leaves.
Each internal node costs two instruction words, and each terminal keeps the
same six-word fixed slot of section24. Hence one slot requires at most
2*511+6*512=4094 instruction words. Four slots cost16376 words. Smaller heights
use the appropriate prefix and leave the rest unreachable. No padding slot
becomes a real match: section24's lower-bound proof applies verbatim. Uniform
DFS generation computes each node and leaf address from public height, node
number, last-left ancestor and rank. It emits the same comparison/branch
instructions, literal key-register IDs and index loads as before. Real versus
padding terminal classification still uses current n, not query data.

Use lanes A1,A2,A3,A4. Misses from lane t<4 branch or fall through to adapter
t+1; misses from lane4 reach COUNT. Each all-right leaf is immediately before
its own continuation, as in section25. COUNT subtracts4 from remaining,
compares to zero and branches to A1 if nonzero, otherwise enters BOUNDARY.
Real hits jump to four persistent stubs which reconstruct
    j=phase_start+phase_length-remaining+t, for lane t in{1,2,3,4},
and enter unchanged terminal recovery. Each stub embeds its fixed t; there is
no per-query lane counter or selection cost. Initialize remaining at each
boundary as before. D=2^119 and2D are divisible by4. Induction over groups
therefore proves remaining is a positive multiple of4 on group entry, every
lane's current index is reconstructed exactly, and the four queries/lookup
steps are precisely the next four of section24. Hits terminate without later
lanes; four misses consume4 before the identical boundary. There is no stale
geometry, skipped lookup, extra target compression or altered insertion.
Thus all outcomes are identical for every salt/start, independently of H-tail510.

At most511D target adapters execute in detection and at most511D/4 countdowns.
Their nonsearch work is4*511D+3*511D/4=2427.25D. The same9196D search bound
and36D recovery bound apply. Terminating index load and transfer cost2 fixed.
    H<=514D+2,
    W<=11659.25D+2+2^40,
    T<=514D+2+(11659.25D+2+2^40)/638.
Leading exponent128.05602714717114 is rounded upward to128.056028. Its slack
exceeds2^107 compression units and covers all fixed terms below2^31. All
compressions, randomness, failed paths and recovery are charged as previously.
This is total work, not parallel time or an average over favorable queries.

Code accounting starts with section24's conservative19078-word ledger. That
ledger includes8158 words for ALL original height-specific lookup fragments.
Remove those fragments entirely: retain10920 words of persistent code, pools,
generator, phase bodies and recovery, conservatively including obsolete control
blocks even if unreachable. Allocate the16376-word arena instead. Reserve512
additional persistent instruction words for four adapter/continuation stubs,
COUNT and hit reconstruction, plus the generator's four-slot outer loop.
Total27808 words=889856 bytes. Add all114624 prior noncode bytes unchanged:
total1004480 bytes<1048576. The arena replaces all static lookup geometries;
there is no second full template copy or emitted-source buffer. Output goes
directly to its final arena addresses. The DFS stack fits existing scratch.
Even all code plus noncode addresses fit below2^16 words and literal branch
operands fit the established256-bit instruction representation. No cache scalar
is duplicated; all four lanes read the same511 registers and arrays. Report
memory_log2_bytes=20 conservatively, including code and generation scratch.

At every rebuild, compute each slot base and continuation before its DFS. The
previous section24 generator already emits geometry and classifies terminal
slots; only branch bases/continuations and the fourfold slot loop differ.
Charge a deliberately generous4096 ordinary operations per geometry block
for stack updates, bit shifts, arithmetic, comparison/branch, address formation,
rank propagation and emitting at most6 words. There are fewer than1024 blocks
per slot, four slots, and at most512 rebuilds, so total new arena generation
work is below2^33 operations. This includes all four slots, not merely their
increment over old generation. Retained initialization/rebuilding costs below
2^32 and hit/boundary routines remain well within the unchanged2^40 reserve.
The512-word extra persistent-code reserve exceeds the instructions required
for the fixed four-slot loop, base updates and the four hit stubs; recursive
DFS is the already retained generator. No new target-specific advice is used.

This version's experiments remain byte-identical and do not execute the arena.
The finite-width/full-width and generated-code evidence limitations persist.
The proof obligations for arena reuse and grouped control are the explicit
code construction, memory ledger and deterministic equivalence above. AI
review, human acceptance and promotion must still be reported separately.

27. Preprocessing field consistency. The expanded uniform arena generation
may use more than the inherited2^31 setup allowance. The claim therefore reports
preprocessing_log2=40, bounding all finite initialization/rebuild construction
work already included in the2^40 fixed reserve above. This field is an upper
bound, not extra work to add a second time. No2^31 preprocessing bound is
claimed for this revision. All full-run and memory bounds remain unchanged.

28. Compact terminals and five-query groups (current controlling revision).
This revision directly uses the four-query construction submitted as
 e93ab052-6b4c-4bee-bcb6-6fdf02f8f9a1, and the published paired predecessor
 a76336a7-eb93-4a24-85c5-a6ff83fb2e6e. It keeps every target call, checkpoint,
cap, recovery operation, heuristic and experiment unchanged. Sections26-27
are historical where their arena size and grouping factor differ below.
The new claimed time exponent is128.055702, memory exponent20 and
preprocessing exponent40. The improvement concerns deterministic control
and code storage; H-tail510 remains an explicitly conditional premise.

Replace each six-word terminal slot by a four-word slot. A real last-left
ancestor has exactly four operations already specified in section24:
compare its cached key with x; branch to lane continuation if unequal;
load its positive literal-address checkpoint index; jump to its lane hit stub.
A padding terminal emits one unconditional jump to the lane continuation,
with three unreachable reserved words. An all-right terminal needs no operation
and is placed immediately before its continuation; omit its entire slot there.
The four-word upper bound still counts that omitted slot conservatively.
All other slots keep their full four words, preserving directly computable
geometry. Internal nodes still emit comparison and conditional branch, with
left fallthrough and right absolute address. Real equality and padding behavior
are identical to section24 for every possible query, including x=U.

Uniform geometry generation needs no retained address map. For subtree height
h>=0 define its reserved size S(h)=2*(2^h-1)+4*2^h=6*2^h-2 words. In preorder,
a nonempty subtree at address b has its node at b,b+1, left subtree at b+2,
and right subtree at b+2+S(h-1). A height-zero terminal occupies four words.
The unique final all-right terminal has no following sibling, so deleting its
four words changes no earlier node/leaf address and puts its continuation
at the start of that terminal's reservation. At emission, do not emit those
four words and start the continuation there. Computing child bases from S
requires shifts, additions and a subtraction, not target-dependent search.
The generator retains the same bounded DFS stack and last-left ancestor/rank
state as before. It emits directly into an inactive arena; no simultaneous
old lookup/template storage is retained or needed.

Use FIVE copies of the active geometry and adapter, lanes1 through5. One
largest fragment costs at most2*511+4*512=3070 words, so five tree reservations
cost15350 words. Reserve32 additional words per lane for physically adjacent
adapter/continuation instructions, so total arena capacity is15510 words.
Real-hit stubs have fixed lane literal t in1..5 and
compute j=phase_start+phase_length-remaining+t before entering recovery.
Each miss from lanes1..4 goes to the next adapter; misses from lane5 go to
COUNT, including the all-right fallthrough. Physically lay out adapter1, tree1, adapter2, tree2, through adapter5, tree5,
then COUNT. Each adapter is immediately before its tree and uses at most32
instruction words; each tree's omitted final terminal is exactly the next
adapter's start (or COUNT for tree5). Emit only the actual adapter instructions,
without executing any reservation padding. Lane bases are computed successively
from actual emitted adapter lengths and S(h)-4 tree lengths, not from maximum
slot capacity. Unused arena capacity is after the full active program and is
unreachable. Thus fallthrough encounters no gap and needs no extra transfer.
Branch bases and continuation offsets are fixed before emission and encoded
explicitly. The separate persistent allowance conservatively also retains
adapter/stub instructions in its bound; the arena allocation additionally
charges their adjacent copies, so physical placement cannot hide storage.

Because phase lengths are not multiples of5, handle the suffix explicitly.
Let L be the phase length (D or2D), and r=L mod5. Since D=2^119, r=3 for
L=D and r=1 for L=2D. At each boundary restore COUNT's three instructions:
    remaining=remaining-5
    compare remaining with r
    branch to lane1 if unequal
The instruction immediately after COUNT is a fixed jump to PRETAIL in persistent
code. It executes at most once per phase and is charged in fixed work. Initialize
remaining=L, execute lane1, and repeat full groups while COUNT branches back.
After floor(L/5) complete groups, remaining=r. The main group never crosses
a boundary: before its final group, remaining=r+5, which is greater than5.

PRETAIL executes only once per phase after all main groups have missed. While
no lookup is active, replace COUNT's first instruction by an unconditional
jump to BOUNDARY; its old other two words become unreachable. Set remaining=5
and enter lane(6-r), executing exactly the final r adapters/lookups. Thus for
r=3 enter lane3, and for r=1 enter lane5. A suffix miss in lane5 reaches patched
COUNT and jumps directly to BOUNDARY, without subtracting5 or comparing again.
On a suffix hit in lane t, the existing hit formula gives
    j=phase_start+L-5+t.
The first suffix lane t=6-r therefore gives phase_start+L-r+1, the next actual
orbit index. Later lanes likewise agree. Hits in main groups retain the old
formula since remaining before them is the number of phase queries left.
The updated COUNT code executes only after PRETAIL finishes all its writes;
its restoration occurs at the next boundary before any next-phase query.
Generation and patching run outside the arena/COUNT instruction words they
write. This is the same abstract charged RAM code-generation model as section26.
No query, target hash, checkpoint, or randomness is duplicated or skipped.

Induction over main groups and the explicit suffix proves every phase queries
exactly the next L states, in order, with identical lookup results and insertion.
Every early hit is the same first hit as section24, reconstructed at the same
index. Cap and failure behavior are identical over all salts/starts. Thus
sufficient event E and its conditional success probability are unchanged;
no new ideal-map or runtime-distribution assumption enters this transformation.

At most511D detection queries execute, including suffix queries. They each
pay the same4 adapter operations. COUNT's subtract/compare/branch executes only
in full main groups, at most511D/5 times. All PRETAIL and restoration work is
fixed per phase, including its writes, assignments and transfers. Each suffix
may require one extra patched COUNT jump on a miss, at most510 jumps total.
There is no per-query suffix test, lane variable or dispatch. The complete
lookup comparison/branch bound remains9196D: fewer terminal instruction words
do not discount any runtime real-key comparison, branch or padding transfer.
Recovery remains36D ordinary operations. Therefore, over every outcome,
    H<=514D+2,
    W<=(4*511+3*511/5+9196+36)D+2+2^40
      =11582.6D+2+2^40,
    T<=514D+2+(11582.6D+2+2^40)/638.
The leading exponent is128.05570147606892. Submit128.055702 rounded upward;
slack exceeds2^106 compression units, whereas all fixed terms are below2^31.
The inherited fixed reserve covers generator work, all boundaries, PRETAIL,
patch/restoration, salt/start initialization and every fixed recovery guard.
The target compression count includes suffix calls once as ordinary detection.

Memory: retain all10920 persistent words of section26 even where old routines
are unused, replace its arena with15510 words, and enlarge its additional
persistent allowance from512 to1024 words. The latter covers five adapters,
COUNT, main/tail entries and hit stubs, COUNT patch/restoration code, base and
size arithmetic and additional generator logic. These are fixed scalar
routines: fewer than64 instructions per lane for adapters/continuations/hits
uses320 words; reserve another512 for COUNT/PRETAIL/restoration and compact
address arithmetic, leaving192 spare. DFS, comparisons, inorder traversal and
emission are already in the retained10920-word generator/code bound.
Total code=(10920+15510+1024)*32=878528 bytes. Add unchanged114624 noncode
bytes: total993152<1048576. State, caches, retained arrays and rebuild stack
are not duplicated for five lanes. All code and data addresses fit below2^16
words, and each256-bit instruction still holds its opcode, scalar identifiers
and small absolute operands. Report memory_log2_bytes=20 conservatively.

Charge4096 ordinary operations per emitted geometry block, as in section26,
including the added subtree-size arithmetic. Fewer than1024 blocks times
five lanes times512 boundaries times4096 operations is below2^34 operations.
COUNT restoration and PRETAIL each use at most128 operations per phase,
with fewer than512 phases, below2^17 operations combined. Prior finite setup
and rebuilding costs below2^32 remain charged. All this work, including
failed paths and initialization, fits strictly below the retained2^40 reserve.
Preprocessing_log2=40 remains a conservative consistent bound. No finite probe
source changes; their measured mask events are not tests of this emitted arena
or a proof of its full-width heuristic. The argument for compact geometry and
suffix correctness is analytic and its exact scope is stated here.

29. Sixty-four-iteration synchronous recovery body (current controlling revision).
This builds directly on the five-query compact-arena construction submitted as
b2a075f6-641e-4f5c-ae2a-d701988797b9. All detection, geometry generation,
suffix handling, probability premises, checkpoints and finite probes remain
unchanged. It changes only bounded synchronous recovery's loop control, while
preserving its literal pointer-update and predecessor-save order in section20.

Allocate64 consecutive copies of the following iteration body:
    a=left; b=right
    x=left; target_adapter(); left=x
    x=right; target_adapter(); right=x
    compare left with right
    branch to VERIFY if equal
On a mismatch, each copy falls through into the next. Copy64 falls through
into RCOUNT. Initialize recovery_remaining=D once before entering copy1.
RCOUNT subtracts64 from recovery_remaining, compares it with zero, and branches
to copy1 if nonzero; otherwise falls through to the existing terminal FAILURE.
Loop entry, exhausted failure and guards are fixed work. D=2^119 is divisible
by64. At each group entry recovery_remaining is a positive multiple of64,
so all64 iterations are authorized and none crosses the D-iteration cap.
An equality in any copy jumps directly to unchanged VERIFY, retaining the
a,b saved by that same iteration; later copies are not executed. No index or
copy number is needed by VERIFY. Pointer and predecessor values are identical
to the first equality in section20 for every orbit. If none occurs, exactly
D synchronous iterations are executed before identical failure. All earlier
recovery guards and right-alignment operations are unchanged. Thus every
outcome and the sufficient event E are preserved over every salt/start,
without adding a runtime or probability heuristic.

Section20 counts22 ordinary operations before the three iteration-control
operations: predecessor saves4, two pointer updates16, equality/branch2.
Retain those22 in each copy, including every source load, destination store,
call and return already charged in the persistent adapter. The two full target
compressions remain separately charged. At most D/64 RCOUNT executions cost3
ordinary operations each. A successful equality bypasses RCOUNT and is safely
overcharged by this upper bound. Synchronous recovery therefore uses at most
(22+3/64)D ordinary operations rather than25D. Right alignment stays bounded
by11D. Total recovery ordinary work is at most33.046875D, replacing36D.
The complete unconditional ledger is
    H<=514D+2,
    W<=11579.646875D+2+2^40,
    T<=514D+2+(11579.646875D+2+2^40)/638.
The leading exponent128.05568892733808 is rounded upward to128.055689.
Rounding slack exceeds2^102 compression units, far above all fixed terms below
2^31. Failed full attempts, alignment and synchronous paths remain charged;
this is a deterministic cap, not an assumption of favorable expected recovery.

Code and memory: allocate1600 additional256-bit instruction words beyond ALL
section28 code and storage. Each synchronous body uses at most24 instructions:
22 ordinary primitives and two complete target invocations, whose existing
compression implementation and its persistent data remain shared and charged
as before. Calls/returns and their scalar copies are among the22, not hidden
between copies. Thus64 copies need at most1536 words. Another64 instruction
words cover RCOUNT, entry/exit transfers and initialization. VERIFY and the
previous recovery implementation remain in the inherited allocation; retaining
old code conservatively requires no subtraction from its ledger. No new per-copy
state, array, instruction template or dynamic generator buffer is allocated.
The existing recovery scalar counter is reused as recovery_remaining. The
fixed sequence can be emitted by a uniform loop, with each copy's equality
branch targeting the same VERIFY label and with all nonterminal paths contiguous.
No target values, target-dependent advice or uncharged stored code are used.
Additional storage is1600*32=51200 bytes. Total charged storage is
993152+51200=1044352 bytes, below1048576 by4224 bytes. It includes all previous
workspace, caches, experiments-as-code reservations, arenas and persistent code.
Report memory_log2_bytes=20 conservatively, so normalized cost equals raw time.

Uniform emission has64 identical fixed bodies and literal branch operands.
Even4096 ordinary operations per emitted instruction consumes fewer than2^23
operations. No separate full template is needed: emit each operation directly
from the persistent generator already allocated; its additional loop/constants
fit within the64 extra words and inherited generator. This new work fits in the
remaining fixed reserve, together with all section28 generation below2^34,
prior setup below2^32 and guards. Preprocessing_log2 remains40. Experiments are
byte-identical and do not execute this64-body RAM program; its correctness,
resource accounting and scope are given by the explicit equivalence and ledger.

30. Terminal reuse of the detection arena (controlling revision).
The direct source is a8b10c74-c96b-4c10-9867-8dd85448a4dd. Retain
sections 1-29 except the synchronous grouping count and its final ledger.
After the first detection hit, the persistent hit stub reconstructs j and k
before leaving the arena. Recovery is terminal: no execution path ever resumes
detection, lookup, phase insertion, or arena rebuilding. Both alignment and
initial recovery guards execute from persistent code, outside that arena.

Once right alignment finishes and before synchronous recovery, generate 512
copies of section29's identical synchronous body directly into the now dead
15510-word detection arena. The emitter and target adapter reside in persistent
code and are never overwritten. Each copy has at most24 instruction words,
including22 ordinary operations and two charged complete compression calls.
Each equality branch names the unchanged persistent VERIFY routine. Copy512
falls through to a three-instruction RCOUNT: subtract512 from recovery_remaining,
compare it with zero, branch to copy1 if nonzero. Exhaustion falls through to
an explicit persistent-failure transfer, counted as fixed work. Initialize
recovery_remaining=D once. At most64 further instruction words cover entry,
RCOUNT and terminal transfers, making capacity512*24+64=12352 words, strictly
less than15510. No lookup, cache key or checkpoint is needed in this storage:
only the detection code arena is overwritten, never arrays or live state.

D=2^119 is divisible by512. At group entry the remaining count is positive
and divisible by512. The next512 bodies are therefore all authorized; on
inequality they fall through in original order. First equality transfers
immediately to VERIFY with the very same saved predecessors as section29.
No later body executes after equality. Without equality exactly D iterations
occur, followed by failure. This proves exact equivalence on every salt/start,
including failures outside E, and preserves H-tail510 without strengthening it.
The initial left/right inequality guard and alignment remain unchanged.

This uses the same explicit charged RAM code-generation model as sections26-29.
It requires no architecture instruction-cache premise: code generation finishes
before entry and no generated word is modified during recovery. The generator
emits operation codes, register identifiers and literal branch addresses directly
into final storage, with no second template or buffer. The existing uniform
emitter of section29 already generates repeated bodies with branch to VERIFY;
replace its public repeat limit64 by512 and its destination by arena_base.
Its bounded integer arithmetic and loop do not depend on target outputs.
The old64-copy recovery body may remain stored and unreachable, conservatively
retaining the entire1044352-byte section29 allocation. New code occupies an
existing arena, and no new scalar register is needed: the emitter's existing
base/counter and recovery_remaining are reused. Thus total live and allocated
storage, including retained old code, stays1044352<1048576 bytes. Claim memory
exponent20 remains conservative. There is no time-memory scoring penalty.

Charge4096 ordinary operations per emitted instruction, even for unchanged
emitter structure. At most12352*4096<2^26 operations generate the recovery
program, once per complete attempt, including any failed attempt that reaches
it. Detection generation below2^34, prior initialization below2^32 and this
additional work remain below the existing2^40 fixed reserve. Guards and output
verification remain charged there. No extra preprocessing or advice is omitted;
preprocessing exponent40 is retained conservatively.

Synchronous recovery now costs at most(22+3/512)D ordinary operations, and
alignment remains at most11D. Replace section29's recovery33.046875D by
33.005859375D. Detection is unchanged. The unconditional full-attempt ledger is
    H<=514D+2,
    W<=11579.605859375D+2+2^40,
    T<=514D+2+(11579.605859375D+2+2^40)/638.
The leading exponent is128.0556887530494. Claim128.055688754, rounded upward.
The rounding margin exceeds2^98 target units and covers2+(2+2^40)/638 by many
orders of magnitude. This small deterministic improvement counts every target
compression, ordinary operation, failed path and runtime code-generation step.
It is total work, not wall time or an average conditioned on a favorable orbit.

All six finite experiment sources and manifests are unchanged. They do not run
the emitted full-width RAM program; their projected mask counts cannot validate
its cost or H-tail510. Its controller equivalence and finite capacity arguments
are analytic above. No new full-width experiment or mathematical proof of the
heuristic is asserted. AI qualification, human acceptance and promotion remain
separate judgments. This package proposes an improvement to the inherited
submitted bound, not an assertion of a currently promoted result.

31. Non-power-of-two recovery groups (controlling revision).
The direct source is published submission 593b3405-fd3a-4dd4-bf29-00cf10ad0a5a.
Retain sections 1-30 except section30's recovery grouping and final ledger.
Use 640 copies of precisely the same 24-word-bounded synchronous body, in
exactly the same dead detection arena. Entry, RCOUNT, suffix transfer and
terminal failure together retain a 64-word reserve. Capacity is
640*24+64=15424 words, below the existing 15510-word arena. All other
allocated code and data remain charged, so memory stays 1044352 bytes.

Here D=2^119=640*q+128 for integer q, because 2^112 is 1 modulo 5.
Initialize recovery_remaining=D. Execute bodies 1 through 640 in order.
On mismatch body640 falls through to RCOUNT, whose instructions are:
    recovery_remaining = recovery_remaining - 640
    compare recovery_remaining with 128
    branch to body1 if unequal
Fallthrough goes to a persistent SUFFIX routine, outside the arena. It writes
an unconditional jump to persistent FAILURE over RCOUNT's first word, then
jumps to body513. Exactly 128 bodies remain from body513 through body640.
Each equality still branches immediately to unchanged persistent VERIFY.
A suffix with no equality reaches the patched RCOUNT and fails. There is
no return to main groups or detection. Patch completion precedes entry into
the suffix; the persistent emitter, SUFFIX and VERIFY never overwrite themselves.
The previous counter comparison's residual words are unreachable after patching.

At main-group entry the number of remaining authorized iterations is
128 plus a positive multiple of 640. The group cannot cross the D cap.
After q full groups, remaining is 128; the suffix executes exactly those
last 128 iterations. Every earlier equality returns with the same saved
predecessors. Thus the exact pointer trajectory, first equality, sufficient
event E, failure behavior and H-tail510 premise are unchanged for every orbit.
This is a deterministic equivalence, without an additional probability premise.
No loop index or body number is needed by VERIFY. The full-width output
checks, target parameters and all six projected experiments are unchanged.

SUFFIX needs one constant store and one transfer in persistent code, with
fixed entry/exit handling. These fit the 64-word reserve; its two literal
addresses are encoded as operands in those words, not a new array. Generation
uses the same uniform emitter, changing its bound from 512 to 640 and final
control operands. Charge 4096 operations per emitted instruction: fewer than
15424*4096 < 2^26 operations. Together with prior generation below 2^34,
setup below 2^32 and all fixed guards/patching, this is below the retained
2^40 fixed-work reserve. No additional workspace, template, advice or live
scalar is needed. Preprocessing exponent 40 remains a conservative upper bound.

There are at most floor(D/640) three-operation main countdowns. Charge at most
3D/640 ordinary operations and put suffix patching/transfers in fixed work.
Synchronous bodies cost 22D ordinary operations; alignment remains at most
11D. Detection remains unchanged. The full unconditional ledger is
    H <= 514D+2,
    W <= (11579.6+3/640)D+2+2^40
       = 11579.6046875D+2+2^40,
    T <= 514D+2+(11579.6046875D+2+2^40)/638.
Its leading exponent is 128.0556887480697208470017532387441234842452133933.
Claim 128.055688749 rounded upward. The rounding margin exceeds 2^97
compression units; fixed additive terms are below 2^31. All failed paths,
construction, memory accesses, target calls and final verification remain charged.
The memory exponent stays 20, so normalized cost equals raw time. This is a
small conditional bound improvement over the direct source, not a claimed
full-width collision, proof of H-tail510, human acceptance or promotion.


32. Carry the right alignment state in the adapter register (controlling revision).
The direct source is b1c57f76-8a05-4f1e-98f2-91132db758ff.
Retain sections 1-31 except the alignment implementation, its repeated ordinary
work bound, and the final ledger. In particular keep every detection query,
the 640-body synchronous recovery program, all target calls, and H-tail510.

The adapter of section15 accepts and returns the orbit state in scalar x.
Its descriptor and compression workspace do not alias the recovery controller,
left, or checkpoint storage. During right alignment no lookup is active and
x has no other live purpose. Let L=j-D-q, so 0<=L<D after the existing guards.
Replace section20's alignment implementation by this literal sequence:
    x=right
    initialize h=0
    while h<L:
        target_adapter()
        h=h+1
    right=x
The loop test is implemented using one comparison and conditional branch per
iteration, with the one initial empty-loop test and entry/exit transfers in
fixed work. Equivalently use an initial L==0 guard then a post-tested loop.
The counter increment is one operation as in the inherited model. The adapter
itself remains exactly four ordinary operations plus one complete target
compression. The loop body therefore costs seven ordinary operations, instead
of eleven: no right-to-x or x-to-right copy occurs inside it. Each outer scalar
copy still costs a load and store, two operations, for four total fixed copies.
Those four operations and the empty-loop guard are charged in fixed work.

An induction proves x=x_(q+h) after h iterations. Initially right=C[q/D]=x_q,
so the assertion holds at zero. The unchanged adapter maps x to f_S(x), so
it holds after each next iteration. On exit the copy gives right=x_(j-D),
identical to the previous implementation. For L=0 the two copies return the
original right unchanged. The left pointer, salt, descriptor, checkpoint arrays,
and all synchronous recovery inputs are unchanged. Intermediate right is dead
inside this loop; no branch, target argument or failure guard reads it there.
Thus every orbit has identical recovery result and identical first synchronous
equality and predecessors. All failures remain bounded. No new heuristic,
probability event, target convention or favorable-runtime premise is introduced.

Alignment has at most D-1 calls and seven ordinary operations per call. Bound
it by 7D, retaining fixed entry, empty-loop handling and the four copies under
the same 2^40 reserve. Synchronous recovery is unchanged at (22+3/640)D ordinary
operations. Detection is unchanged. The unconditional ledger becomes
    H <= 514D+2,
    W <= (11575.6+3/640)D+2+2^40
       = 11575.6046875D+2+2^40,
    T <= 514D+2+(11575.6046875D+2+2^40)/638.
Here D=2^119 and C=638. The leading exponent is
128.0556717506708727811465453096234081759046430632.
Claim 128.055671751 rounded upward. The exponent slack exceeds 3.29e-10,
which at this scale gives more than 2^96 compression units; all fixed additive
terms are below 2^31. This is a total-work cap over every salt/start, including
all failed attempts, not an expected successful runtime. The prior bound was
128.055688749. Both memory exponents remain 20, so raw and normalized costs
coincide. The improvement removes repeated state copies, not target work.

No new state, template, generated arena or code block is allocated. The scalar
x, right and alignment counter already exist. Moving two copies to loop entry
and exit replaces the old repeated copies; the identical number of static copy
instructions and the same loop tests suffice. All code and storage reservations
remain 1044352 bytes below one MiB. Fixed generation stays below 2^34, setup
below 2^32, and added fixed copy/guard work is below 128 operations; these fit
in the unchanged 2^40 reserve. Preprocessing remains conservatively 40.

All six projected experiment sources and their manifest remain byte-identical
to the direct source. They do not execute the full-width RAM algorithm or prove
H-tail510. No full-width collision, measured total attack cost, new empirical
success frequency, human acceptance or promotion is asserted. The equivalence
and savings here are analytic and preserve all previously disclosed limitations.


33. Retain the left state in x across synchronous iterations (controlling revision).
The direct source is 12b54238-d443-4d59-ab25-f791a0baac4d. Retain sections
1-32 except the synchronous body and its resulting ledger. Alignment is exactly
section32, including its final copy to right. Before entering synchronous
recovery, copy left to x once. Replace each of the 640 generated bodies by:
    a=x
    b=right
    x=right
    target_adapter()
    right=x
    x=a
    target_adapter()
    compare x with right
    branch to VERIFY_LEFT_IN_X if equal
The new persistent VERIFY_LEFT_IN_X entry copies x to left, then falls through
to unchanged VERIFY. The exhausted path still goes to FAILURE. RCOUNT, the
128-body suffix, patching, grouping and the bound D=2^119 are unchanged.

Each scalar copy is explicitly a load and store, costing two operations as
in section20. The five copies cost ten operations. Each of the two adapters
costs four ordinary operations and one full target compression, as specified
in section15. The final comparison and conditional branch cost two operations.
Thus each body uses exactly 20 ordinary operations and two complete target
compressions, replacing 22 ordinary operations and the same two compressions.
The right target call precedes the left call here. The target is deterministic,
its descriptor is read-only and its private workspace is disjoint from these
scalars, so exchanging these independent evaluations changes neither result.
The salt and both input words are unchanged. No target work is discounted.

Invariant at body entry: x equals the old body's left state and right equals
its right state. First a,b save the same predecessors. The right call computes
f_S(b), which is retained in right. Restoring a to x and calling the adapter
computes f_S(a) in x. The comparison is consequently identical to the old
left/right comparison. On mismatch the invariant holds for the next body,
including across RCOUNT and suffix entry, whose instructions do not touch x.
On equality the new fixed entry restores left, and VERIFY sees exactly the
old a,b,left,right values. Only fixed setup and that terminal entry read left
after the initial guard. The exhausted failure path needs no left value.
Consequently every salt/start has identical first synchronous equality, saved
predecessors, full collision check and outcome. No extra successful orbit,
favorable runtime assumption or probability premise is used. H-tail510 and
its limitations remain exactly inherited, as do all six finite probes.

Each generated body needs at most 22 instruction words (20 ordinary plus two
complete target invocations). Retain the former 24-word reservation per body,
so the same 15424-word arena bound holds with no new allocation. The emitter
writes the literal sequence directly using the inherited generation mechanism;
no second template or additional state is needed. The fixed entry copy and
VERIFY_LEFT_IN_X copy require four primitive instruction words plus an entry
transfer if needed, within the 64-word persistent entry/suffix/control reserve.
They reuse existing scalars x,left,right,a,b and add no register or data slot.
The persistent entry is outside the overwritten detection arena. The unchanged
fixed operations remain below 2^40, including emission below 2^26, detection
generation below 2^34, setup below 2^32, and fewer than 128 new entry/exit
operations. Retain all old storage, including unreachable old bodies, for a
conservative total of 1044352 bytes. Report memory exponent20. Preprocessing
exponent40 and zero nonuniform advice remain conservative.

Synchronous recovery now costs at most (20+3/640)D ordinary operations.
Alignment stays at most7D; detection is unchanged. For every salt/start,
including every failure path, the unconditional full-attempt ledger is
    H <= 514D+2,
    W <= (11573.6+3/640)D+2+2^40
       = 11573.6046875D+2+2^40,
    T <= 514D+2+(11573.6046875D+2+2^40)/638.
The leading exponent, using D=2^119 and C=638, is
128.0556632518963513189261168988775186570846893000562797796686.
Claim128.055663252 rounded upward. The positive gap exceeds 1.03e-10 in
log2 units and more than2^94 target compression units, whereas all fixed
additive terms are below2^31. Thus the rounding covers fixed terms as well.
Memory stays at most one MiB, so normalized and raw exponents coincide.
This improves the direct source's submitted128.055671751 bound analytically.
It is not a full-width collision, measured attack runtime, proof of H-tail510,
human acceptance or promotion. Projected probes do not execute this emitted
RAM body; correctness and cost of the change are the explicit analytic claims
above. All target conventions, full-output verification, experiments and their
manifest remain unchanged. No empirical outcome is newly asserted.


34. Pack 700 recovery bodies into the existing arena (controlling revision).
The direct source is e5b1a0ab-de60-41a6-8dca-fe7e48282403. Retain sections
1-33 except the recovery grouping, suffix entry and final ledger. Section33's
literal synchronous body remains unchanged: twenty ordinary instructions and
two complete target invocations, at most 22 instruction words. Use that actual
bound rather than its retained 24-word reservation. Emit 700 such bodies into
the same dead 15510-word detection arena. With the same 64-word control reserve,
700*22+64=15464 words fit. The persistent emitter and adapter are outside this
arena. No detection execution resumes after recovery begins.

Write D=2^119=700*q+88, where q=floor(D/700). Initialize the existing
recovery_remaining scalar to D. After each complete group of 700 mismatch
bodies, RCOUNT subtracts 700, compares the result with 88, and conditionally
branches to body1 on inequality. Fallthrough enters persistent SUFFIX. SUFFIX
patches RCOUNT's first word to an unconditional transfer to persistent FAILURE,
then transfers to body613. Bodies613 through700 are exactly 88 bodies. The
patched RCOUNT then fails if no equality has occurred. Each body still branches
immediately on equality to VERIFY_LEFT_IN_X, which restores left and enters
the unchanged full verifier. Constant operands 700,88 and the body613 address
replace the predecessor operands; they require no additional scalar or array.

At entry to each main group, remaining is 88 plus a positive multiple of700.
After q groups it is88. Consequently precisely D synchronous iterations execute
on an exhausted path. An earlier equality executes exactly the same prefix of
section33's literal body sequence and retains the same predecessors. The
countdown, patch and transfer instructions do not read or change x,right,a,b,
the salt or target descriptor. Induction over bodies therefore proves identical
first equality and output, or identical failure, for every salt and start.
Alignment, detection, H-tail510 and the complete target relation are unchanged.
No new probabilistic assertion or favorable-path assumption is introduced.

Generation emits directly into the reused arena using the existing uniform
emitter. Even charging4096 ordinary operations per emitted instruction,
15464*4096<2^26. Detection generation remains below2^34, setup below2^32,
and suffix patches, entry copies and fixed guards fit the retained2^40 fixed
reserve. No simultaneous source template is stored. Persistent control uses
the same instructions and operand widths as section31, with changed constants.
The entire old allocation, including retained unreachable code, remains charged
at1044352 bytes; the arena has not grown. Memory exponent20, preprocessing
exponent40 and zero nonuniform advice remain conservative.

There are floor(D/700) main countdowns of three ordinary operations each.
All suffix handling is fixed work. Synchronous body work stays20D, alignment
stays7D, and detection is unchanged. The unconditional full-attempt ledger is
    H <= 514D+2,
    W <= (11573.6+3/700)D+2+2^40,
    T <= 514D+2+((11573.6+3/700)D+2+2^40)/638.
With C=638, the leading exponent computed at70 decimal digits is
128.0556632501890031931814174175881351228560927047295130820754627543222.
Claim128.055663251 rounded upward. The logarithmic slack exceeds8.10e-10,
providing more than2^97 compression units, while fixed additive terms are
below2^31. Thus fixed work and all failed paths fit the submitted total-work
bound. Raw and normalized costs coincide because memory remains below one MiB.
This improves the direct source's128.055663252 bound without reducing any
complete target calls or changing its unresolved full-width heuristic.

All six finite projected probes and their manifest remain byte-identical to
the direct source. They do not execute this generated RAM controller and do
not prove H-tail510. The new controller equivalence, code capacity and operation
ledger are analytic claims above. No measured full-width collision, unconditional
success theorem, human acceptance or promotion is asserted.


35. Direct right-state adapter and 965-body recovery groups (controlling revision).
Direct source: 72c43152-e6a2-4874-ac4f-319166b6b02b. Retain sections1-34
except the synchronous body, its grouping and the final ledger, superseded here.
This revision uses neither the packed-target implementation nor the claim of
rejected submission 0d9c823c-eb03-43ce-b274-d8f0fd12fb0d. All complete hash calls,
H-tail510, its conditional probability and six finite probes remain unchanged.

Section15's adapter has four ordinary operations: store the input scalar at
the second message-word address; transfer to the target compression; return;
load the first 256 output bits from its output address into the input scalar.
Its persistent descriptor addresses message/output memory, NOT a named orbit
scalar. Create adapter_right with those same four operations, replacing only
the source scalar of the first store and destination scalar of the last load
by right. Keep the descriptor, salt message word, IV, flags11, length64,
counter0, rounds3 and target workspace identical. Its two middle operations
are identical. Thus it maps right to f_S(right), leaves x alone, and costs four
ordinary operations and exactly one full selected target compression. The
existing adapter maps x to f_S(x) and leaves right alone. Both target workspaces
are disjoint from x,right,a,b. The shared message/output memory need retain
nothing between calls; the next store replaces the only variable message word.
No dynamic scalar indexing or descriptor mutation is introduced.

After section32's alignment and the unchanged initial left!=right guard,
copy left to x once, as before. Emit the following literal body:
    a=x                       # load and store: 2 ordinary operations
    b=right                   # load and store: 2 ordinary operations
    adapter_right()           # 4 ordinary operations + 1 target compression
    target_adapter()          # 4 ordinary operations + 1 target compression
    compare x with right      # 1 ordinary operation
    branch VERIFY_LEFT_IN_X if equal  # 1 ordinary operation
The total is14 ordinary operations and two complete target compressions,
occupying at most16 instruction words. The four adapter instructions are
emitted inline at each site, including their target transfer/return. Here
return resumes at the site's immediately following output-load instruction,
exactly the same target interface and instruction convention as sections15
and33. No extra ordinary subroutine call is claimed free. The target calls
still receive the same shared descriptor. A separate named right-adapter
subroutine and its additional linkage are unnecessary.

Invariant at entry: x and right are the old left and right states. The first
two copies save their exact predecessors. The right adapter yields f_S(b)
without overwriting x; the original adapter yields f_S(a) without overwriting
right. Their final equality comparison is therefore identical to section33.
A mismatch preserves the invariant for the next body. Equality enters the
existing VERIFY_LEFT_IN_X, which restores left and invokes the unchanged full
verification with the same a,b,left,right. Every failure, first equality,
full-output check and returned message pair is identical for every salt/start.
The order of target calls is unchanged from section33. Only dead intermediate
copies x=right, right=x and x=a have been removed; their total cost was six
ordinary operations. The construction never substitutes an internal CV,
truncated digest, changed initial state or reduced message domain.

Emit965 bodies into the same15510-word dead detection arena. Reserve64 words
for its existing controls, giving965*16+64=15504 words, within capacity.
D=2^119=965*q+828. Initialize recovery_remaining=D. After a full main group,
RCOUNT subtracts965, compares the result with828, and branches to body1 if
unequal. Fallthrough enters the persistent suffix routine. That routine patches
RCOUNT's first instruction to transfer to FAILURE and enters body138. The
bodies138 through965 are exactly828 bodies; the patched countdown then fails.
As before all equality branches terminate immediately. q is positive and every
main-group entry has remaining=828 plus a positive multiple of965. Thus an
exhausted path executes exactly D bodies. Neither COUNT nor suffix touches
x,right,a,b or the target descriptor. Grouping preserves the same sequence of
body operations, including the first hit and every failed path.

The previous scalar allocations, descriptor, code, generator and working memory
are retained. No extra data scalar, descriptor, workspace, or persistent adapter
is needed: source/destination register IDs replace literals in the emitted body.
The existing uniform emitter writes directly into the old arena, without a
simultaneous template. At4096 operations per emitted instruction,15504*4096
is below2^26. Detection generation stays below2^34, prior setup below2^32;
all fixed guards, copies, verification entries and suffix patches remain within
2^40 ordinary operations. Total reserved storage remains1044352 bytes below
one MiB, including retained unreachable code. All scalar and code addresses
still fit the inherited256-bit instruction representation. Report memory
exponent20 and preprocessing exponent40 conservatively, zero advice.

Detection ordinary work stays unchanged, alignment stays7D and synchronous
ordinary work decreases from20D to14D. At most floor(D/965) three-operation
main countdowns execute; suffix handling is fixed work. For every salt/start,
including failures, the unconditional resource cap is therefore
    H <= 514D+2,
    W <= (11567.6+3/965)D+2+2^40,
    T <= 514D+2+((11567.6+3/965)D+2+2^40)/638.
Here638 is the exact round3 contract normalization. At75-digit Decimal
precision the leading exponent is
128.055637748563779361533667069018943099190094490201959953290212562159709966.
Claim128.055637749, rounded upward. Its log2 slack exceeds4.36e-10 and
provides more than2^96 target units, whereas fixed terms are below2^31.
Raw and normalized bounds coincide at memory exponent20. This is an analytic
total-work saving over the source's128.055663251, with no parallel latency
discount, omitted failed trials or favorable-path conditioning.

No experiment source changes. The inherited finite projected probes do not
execute this generated RAM controller or establish H-tail510. The evidence
for this change is deterministic adapter equivalence, the body invariant,
exact suffix count and the explicit instruction/storage ledger. The original
full-width probability premise and all its uncertainty remain disclosed.
No full-width collision, unconditional theorem, measured total attack work,
human acceptance or promotion is asserted.


36. Alternate recovery destinations and enforce a joint target-call cap.
This revision builds on submission1f9cf13f-0c57-4872-9090-f400a4f3ab9c.
Keep sections1-35 except the synchronous body, recovery limit, grouping and
final ledger, superseded here. H-tail510 and sufficient event E are unchanged.
The two changes below preserve success on E; outside E, early capped failure
is permitted. Every returned answer still receives full ordinary verification.

Use the same four-operation adapter with separately named source/destination
scalars. A call A(u,v) stores u at the variable message-word address, transfers
to the complete selected compression, returns, and loads its full output into
v. It leaves u unchanged when u!=v and never aliases the other orbit scalars.
Its persistent descriptor and disjoint target workspace are exactly section35.
Each invocation costs four ordinary operations and one full target compression.
Source and destination names are literal instruction operands. No descriptor
patching or extra ordinary subroutine call is used: emit the four instructions
inline, including the charged target transfer and return, at every call site.

After alignment put the initial left state in x, with right the initial right.
Alternate the following literal bodies, with a,b the existing other two scalars:
    ODD:  A(right,b); A(x,a); compare a,b; branch ODD_HIT if equal
    EVEN: A(b,right); A(a,x); compare x,right; branch EVEN_HIT if equal
Each body costs10 ordinary operations plus two target compressions, at most12
instruction words. At odd entry x,right are the two current states; after its
calls a,b are their images and x,right retain their predecessors. At even
entry a,b are current; after calls x,right are images and a,b predecessors.
Induction establishes exactly the original abstract sequence of state pairs.
There is no runtime parity test: the two bodies are physically alternated.
A mismatch falls through to the next emitted body. ODD_HIT copies x to a and
right to b (four ordinary operations), then enters FULL_VERIFY. EVEN_HIT
already has a,b as predecessors and enters FULL_VERIFY directly. FULL_VERIFY
implements the last part of section4: if a==b fail; construct M_S(a),M_S(b);
recompute the two complete digests and compare all256 bits and distinctness.
It does NOT read left or the current image scalars, which are dead after the
branch. Equality was tested before an odd hit overwrites a,b. Thus these fixed
hit stubs cannot lose either predecessor or silently accept a near-collision.
The final verifier's full two target calls and constant ordinary work remain
charged even though the prior equality already implies their digest equality.

Now bound recovery calls jointly with detection, rather than separately taking
three unrelated worst cases. At entry after a hit let L=j-D-q, as in section32,
so0<=L<D. Exactly j detection and L alignment calls have occurred. Compute
    R=min(D, floor((513D-j-L)/2)).
All these integers fit256 bits. Since j<=511D and L<D, the expression is
positive and R>=D/2. Execute at most R synchronous iterations instead of D.
If no equality occurs, fail. This is a deterministic explicit budget check at
entry, not an assumed average or a favorable-outcome time measurement.
Every path uses at most513D+2 complete target calls, including final checking.
An early detection failure has at most511D. A recovery failure has at most
j+L+2R<=513D. No extra target evaluation is required to compute this budget.

On E, section5 gives k=ceil(mu/D)*D, j=k+lambda and first equality at
    t=mu-k+D, with1<=t<=D.
The alignment count L satisfies0<=L<D. Therefore
    j+L+2t = lambda+2mu-k+2D+L
            <= lambda+mu+2D+L
            < 513D,
using k>=mu and mu+lambda<=510D. Thus2t<=513D-j-L, so t<=R. The new cap
cannot remove the sufficient-event collision. Original recovery guards and
first-hit reasoning remain unchanged. On E it reaches the same first equality
and predecessors. Outside E it may fail earlier and cannot return a false
collision. The identical H-tail510 premise therefore still implies algorithmic
success probability at least0.39; no new fixed-target probability hypothesis
is needed. No new empirical probability is asserted.

Pack1286 alternating bodies into the dead15510-word arena, with the existing
64 control words:1286*12+64=15496 words fit. A complete group has even length
and begins odd, ends even, restoring current states to x,right. Compute q_R
and r_R with R=1286*q_R+r_R, 0<=r_R<1286. q_R is positive because R>=2^118.
Initialize remaining=R; COUNT subtracts1286, compares with r_R, branches to
body1 if unequal. After q_R groups, if r_R=0 fail. Otherwise patch COUNT's
first word to transfer to failure and enter body(1287-r_R), executing exactly
r_R bodies. If r_R is odd that entry is an even body: before entry copy x to
a and right to b, four fixed ordinary operations. If r_R is even, entry is odd
and needs no copy. These one-time parity decisions and transfers occur in the
persistent suffix prelude; no repeated body pays a parity branch. In both
cases the entering named pair holds the current abstract states. The suffix
ends at even body1286, then patched COUNT fails. Equality still terminates
immediately through the appropriate literal hit stub. Precisely R abstract
iterations occur on exhaustion; early equality follows the same pair prefix.

Compute q_R,r_R by binary long division, not an unpriced division primitive.
Initialize quotient and remainder to zero. Process bits118 down to0 of R,
including the possible bit119 when R=D, so use120 iterations. Each step extracts
one bit with shift/AND, shifts remainder and inserts that bit, shifts quotient,
compares remainder with1286, conditionally subtracts1286 and ORs1 into the
quotient, and decrements/tests the bit counter. Including branches and loads,
32 ordinary operations per bit is ample; total is below4096. Test r_R parity
by AND1 and compare, and compute suffix address as arena_base plus12 times
(1286-r_R); multiplication by12 is two shifts and an addition. Patch a literal
unconditional transfer with that small absolute address before executing it.
All generation and patching executes in persistent code outside the arena.
The patch cannot change live descriptor, checkpoint or orbit data.

Reserve an additional96 persistent instruction/constant words and32 data words
for cap arithmetic, binary-division loop, suffix parity preparation, address
patching and hit stubs. A loop implementation needs no unrolling: reserve24
words for budget/min and entry,16 for the division body/control,24 for suffix
and target patch,16 for the two hit stubs and16 for constants/linkage. This is
96 total; fixed512-boundary detection code is unchanged. The additional32 data
words include120-bit counters, quotient, remainder, R and address temporaries.
There is no second target descriptor, arena or source template. Retain all old
storage conservatively, even obsolete adapters. New total memory is
1044352+128*32=1048448 bytes, below1048576. Memory exponent20 remains safe.
All code/data addresses remain below2^16 words. Uniform emission of15496
instructions at4096 operations each is below2^26; existing detection generation
below2^34, prior setup below2^32 and all new fixed work fit2^40. Preprocessing
exponent40 stays conservative; zero nonuniform advice remains unchanged.

Synchronous ordinary work is at most10D, alignment at most7D and detection is
unchanged. COUNT executes at mostD/1286 times; parity preparation, long division,
all hit stubs and suffix patches are fixed work. For every salt/start, including
all failures, the unconditional total bound is
    H <= 513D+2,
    W <= (11563.6+3/1286)D+2+2^40,
    T <= 513D+2+((11563.6+3/1286)D+2+2^40)/638.
The leading exponent at75-digit Decimal precision is
128.052906999616548331708018786046713852851064469082654136260146905562004235.
Claim128.052907001 rounds upward with more than2^98 compression units of
slack, covering fixed terms below2^31. Raw and normalized exponents coincide.
The gain comes from eliminating repeated copies and bounding actual combined
target work, without omitting failures or using a parallel wall-clock discount.

All six projected experiment sources are unchanged. They do not execute the
new emitted controller or establish H-tail510. This section's evidence is the
explicit adapters, alternating-state invariant, sufficient-event budget proof,
exact variable-length suffix and instruction/storage ledger. The full-width
heuristic and its limitations remain unresolved; no unconditional theorem,
full-width executed witness, human acceptance or promotion is asserted.

37. Paired alignment loop (controlling revision).
Direct source: submission 7755668, evaluated commit
f918f1d1fb2479e6f225ec2413fdf650df7bfa8d. Retain sections 1-36 except
alignment's implementation and its ordinary-work ledger. In particular all
complete compression calls, the joint cap, synchronous recovery, H-tail510,
its sufficient event E, and finite probe sources remain unchanged.

At alignment entry let L=j-D-q, with 0<=L<D as before. Copy right to x,
compute p=L>>1 and e=L AND 1. If e is nonzero invoke the unchanged four-operation
adapter once. If p=0 skip the paired loop; otherwise execute:
    PAIR: target_adapter()
          target_adapter()
          p=p-1
          compare p with zero
          branch PAIR if nonzero
Finally copy x to right. These are the same adapter and disjoint workspace
of section32. The loop contains eight ordinary adapter operations and two
complete target compressions, followed by three ordinary counter operations.
All source stores, target transfers and returns, and destination loads are
charged; the two calls are emitted inline, so no extra subroutine is free.
The parity branch, initial zero test, shifts, AND, copies and exit transfers
are fixed work. The paired loop uses 11*floor(L/2) ordinary operations and
the odd prefix at most four. Thus its repeated ordinary work is at most
5.5L+4, which is bounded by 5.5D plus fixed work.

After the optional prefix and i paired bodies, x=x_(q+e+2i). This holds
initially because right=C[q/D]=x_q and each adapter applies exactly f_S.
At loop exit e+2p_initial=L, so the final copy gives x_(j-D), identical to
section32. L=0 executes neither prefix nor pair. L=1 executes only the prefix.
For all larger L the decreasing positive pair counter terminates after exactly
floor(L/2) bodies. No intermediate alignment state is read by detection, lookup,
recovery or a failure guard. The left state, checkpoints and salt stay unchanged.
Hence every salt/start has the same aligned pointers, the same first subsequent
synchronous equality and the same predecessors and verification result. Target
count j+L is unchanged, so section36's R and sufficient-event proof apply
verbatim. This modification adds no probability premise and makes no claim that
the full-width heuristic has been established.

Place the new literal alignment routine, its constants and temporaries in a
128-word block carved out of the obsolete 1536-word sixty-four-body code
reservation introduced in section29. That old body is unreachable: section36
emits its synchronous bodies into the separate 15510-word detection arena.
Its persistent FULL_VERIFY, descriptor, generator and control routines are
outside the reclaimed body block and are not changed. Retain the other 1408
obsolete body words conservatively. Thus this revision replaces 128 allocated
words with 128 allocated words; it adds no memory. Reserve 64 instruction and
constant words for the paired routine (two five-word target invocations, three
countdown instructions, two two-operation copies, parity and initial guards,
linkage, and constants fit); reserve 64 scalar words for p,e and all temporary
work, far more than needed. No code generation or alternate code arena is
needed for this fixed routine. All addresses remain within the inherited
16-bit address range. Old alignment code may remain allocated and unreachable.
Total memory stays 1048448 bytes, below one MiB, and the reported exponent20
remains conservative. Initializing these words and all new fixed instructions
is below 4096 ordinary operations; together with the unchanged earlier setup
and generation it fits the existing 2^40 fixed-work reserve. Preprocessing40
and zero nonuniform advice remain unchanged.

Replace alignment's 7D ordinary-work term by 5.5D. The odd-prefix overcharge
and all fixed entry/exit work are included in the fixed reserve. Every path,
including failure, obeys
    H <= 513D+2,
    W <= (11562.1+3/1286)D+2+2^40,
    T <= 513D+2+((11562.1+3/1286)D+2+2^40)/638.
For D=2^119, the leading exponent at 75 decimal digits is
128.052900613313463595732733595398300888308847603336645144510170206366487670.
Claim128.052900614 rounds upward with more than 2^96 compression units of
slack, whereas fixed terms are below2^31. Raw and normalized costs coincide.
The improvement is a bounded ordinary-control saving, not a reduced target-call
price, measured full-width runtime, successful full-width collision, human
acceptance or promotion. The six projected probes do not execute this literal
paired alignment routine. Their finite scope and the unresolved extrapolation
to H-tail510 remain precisely those of the direct source.


38. 128-call alignment groups (controlling revision).
Direct source: f948cec9-e2fb-42ca-88ee-db7a4157f870, evaluated commit
772885104bff6dff4a6d0a41a986e4c1d52ed5d9. Retain sections1-37 except the
alignment routine and its final work ledger, superseded here. In particular
H-tail510, E, the joint cap, detection, synchronous recovery and six finite
probe sources are unchanged.

At alignment entry copy right to x and compute p=L>>7, e=L AND127.
First execute e individual adapter calls using a countdown loop: after each
call decrement e, compare with zero and branch if nonzero. An initial zero
test skips this loop when e=0. Its cost is at most7*127=889 ordinary operations,
charged as fixed work, and exactly the original initial e target calls.
If p=0 skip the main loop. Otherwise execute a literal inline group of128
consecutive target_adapter invocations, then decrement p, compare with zero,
and branch to the first invocation if nonzero. Finally copy x to right.
Each invocation uses exactly the four charged operations of section37,
including store, target transfer, return and output load. There is no free
subroutine linkage. Each group costs512+3=515 ordinary operations and128
complete target compressions. Thus repeated main work is at most
(4+3/128)L <= (4+3/128)D, with remainder and entry/exit in fixed work.

After the remainder and i groups, x=x_(q+e_initial+128i). Induction follows
from the same complete f_S adapter, whose workspace is disjoint from orbit
scalars. On exit e_initial+128*p_initial=L, so right becomes exactly x_(j-D).
L=0 skips both loops; L<128 executes only the remainder. No intermediate
alignment value is observed by any lookup, guard or recovery. Every salt/start
therefore has exactly the same target calls in the same order, aligned states,
joint budget R, first synchronous equality and full-verification result as
section37. This preserves success on E without a new probability premise.
The argument remains conditional on H-tail510, not an established full-width
success theorem. The finite probes do not execute this literal RAM routine.

Replace section37's128-word block and another672 words from the same obsolete
1536-word reservation by an800-word block. Reserve736 instruction/constant words
and64 scalar words. The main group needs at most128*5+3=643 instruction words;
the remainder loop needs at most8, leaving85 for guards, two scalar copies,
shift/AND, entry/exit, constants and linkage. No generated code, second template
or new workspace is needed. The section36 detection arena, persistent verifier,
descriptor and generator lie outside this reclaimed obsolete body block.
All800 words were already allocated; retain the other736 obsolete words.
Total storage remains1048448 bytes, below one MiB; all word addresses remain
below2^16. Memory exponent20 stays conservative. The literal uniform program
is not advice or precomputed collision data. Loading/initializing this block
and the fewer than1024 extra fixed runtime operations fits an additional2^24
ordinary operations conservatively. To avoid relying on hidden slack in the
inherited fixed reserve, increase the final fixed bound from2^40 to2^41 and
report preprocessing exponent41. This covers all inherited setup plus the new
block and remainder even when L is maximal. No failed path is omitted.

Relative to section37 replace5.5D by(4+3/128)D. Every path satisfies
    H <= 513D+2,
    W <= (11560.6234375+3/1286)D+2+2^41,
    T <= 513D+2+((11560.6234375+3/1286)D+2+2^41)/638.
Here D=2^119 and638 is the selected round3 reference operation cost.
The leading exponent is
128.052894326768753647403590706261101405824070737691173535982428275846703132.
Claim128.052894327 rounds upward with over2^95 target units of slack;
the fixed addends are below2^32. Normalized time equals raw time at memory20.
This is an analytic bounded ordinary-control saving. No executed full-width
collision, human acceptance, promotion, or measured full-width work is claimed.
