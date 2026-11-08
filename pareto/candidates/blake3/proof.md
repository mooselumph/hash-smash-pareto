# Sparse-checkpoint salted rho for complete BLAKE3-r3

1. Scope and result. This is a classical ordinary collision construction for
complete unkeyed BLAKE3 with prefix rounds 0,1,2 in every compression. It uses
one explicit fixed-target heuristic H-cap511. Conditional on that premise,
its success probability is at least 0.39. Its deterministic total work is below
2^128.119 selected-target compression units, including failures, and all memory
is at most 2^20 bytes. Consequently its normalized time-memory cost is 128.119.
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

10. Branch-coded variable-height exact search. Let h=bit_length(n) for
n>0. Store internal keys at absolute word addresses 1..2^h-1 in K[0..511],
and their indices at addresses 512+a in J[0..511]. Other objects are disjoint.
Build the perfect tree in inorder from sorted real records followed by
(U,NONE) padding, where U=2^256-1. Cache root key K[1] in root_key.

For each possible height h=1..9, use a fixed code fragment for this tree's
geometry, with one block per internal node and one per external leaf.
The geometry and all RAM/code addresses are uniform constants, independent of
salt, state, key values or target outputs. Select this fragment only at rebuild.
Runtime uses a fixed register set x,y,k,root_key and the controller registers;
there is no register per tree node and no embedded data-key advice.

The root block compares root_key<x and conditionally branches to its right
subtree; otherwise execution falls through into the left subtree. Cost two.
Every non-root node a performs:

    y = LOAD_LITERAL(a)
    b = (y < x)
    if b: goto RIGHT_CHILD_BLOCK_a
    # left-child block is next in code

LOAD_LITERAL(a) is one priced load at the small absolute address encoded in
the instruction. It performs no runtime index arithmetic. This is the same
word-RAM load primitive, with a literal operand instead of a register operand.
The comparison and branch cost one each, so each such node costs three.
Lay blocks in preorder. Every external leaf exits to the common MISS/RECOVER
routing, so execution cannot fall through from a finished left subtree to a
right subtree. There is no extra unconditional branch at an internal node.

Each external leaf u has a statically determined last-left ancestor
    a=u>>(t(u)+1),
where t(u) counts trailing one bits in the leaf number. This is calculated
only during uniform code generation, not at query time. If a=0 its block
transfers directly to MISS. Otherwise its block is:

    y = LOAD_LITERAL(a)
    if y != x: goto MISS
    k = LOAD_LITERAL(512+a)
    if k != NONE: goto RECOVER
    goto MISS

The key load and equality comparison/branch cost three. The terminal index
load costs one only on equality. The NONE/hit test and leaf transfers are
within the 24-operation controller allowance, never silently omitted.
The empty phase goes directly to MISS. Every nonempty query therefore costs
at most 2+3(h-1)+3=3h+2 key-search operations, plus a single conditional index
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
index, orbit controller, sufficient event and H-cap511 premise are unchanged
for every query. No distributional or machine-specific timing premise is added.

The search precedes checkpoint insertion. Over the full bounded run n=0
lasts D queries, each n=1..509 lasts D queries, and n=510 lasts 2D queries.
These sum to B=512D. Early termination only reduces work. The height sum is
sum_(n=1)^510 bit_length(n)+9=4088+9=4097. There are 511 nonempty-phase D
intervals. The key-only search work, through equality comparison/branch, is
(3*4097+2*511)*D=13313D. Section 14 proves at most 2D+3 conditional index
loads in the entire run. Thus search work is at most13315D+3. All key loads,
comparisons and branches remain charged on every query. Padding matches and
failed recovery are covered by that deterministic bound.
The detection controller uses at most 24 nonsearch operations per call,
explicitly implemented as in section 15. This includes a 4-operation target
adapter, 8 routing operations, counter increment, cap/mask/guard tests,
continuation branches and register moves. Constants and the phase body are
selected at initialization/rebuild only.
Recovery retains a separate 128-operation allowance per target call.

Detection costs at most m+D compressions, right reconstruction fewer than D,
synchronous recovery at most 2D, final verification two. Thus every random
choice and failure path obeys
    H <= m+4D+2 =515D+2,
    W <=24*(m+D)+13315D+3+128*(3D+2)+2^40
       =25987D+259+2^40,
    T <=H+W/638.
With D=2^119=2^128/512, the leading coefficient on 2^128 is
    515/512 + 25987/(512*638).
Its logarithm is 0.11824544020126. The conservative claim 128.119 leaves
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
K and J together1024*32=32768. Reserve8192 for live words, buffers, compression
workspace and rebuild stack, and524288 bytes for uniform code/constants.
Total614336 bytes, below1048576. Claim memory_log2_bytes=20 conservatively,
so normalized time-memory cost equals the raw time exponent.

Across h=1..9 there are sum(2^h-1)=1013 internal node blocks and
sum(2^h)=1022 external leaf blocks. Nine root blocks cost two instructions;
the other1004 nodes cost three each, total3030. At most eight instructions
per leaf includes key load, equality comparison/branch, index load, NONE
comparison/branch, common-continuation transfer and one spare:8176 more.
Reserve4096 additional instruction words/constants for all shared initialization,
phase control, insertion, rebuild, adapter and recovery routines. Total15302
words is below the16384-word code reservation. Encode each instruction in
one32-byte word: opcodes, fixed register IDs and small literal addresses all
fit comfortably. All RAM/code addresses are below2^16 words. Full-width U/NONE
and other constants occupy the included pool/registers initialized once, not
oversized instruction immediates. Uniform code generation uses loops and fixed
geometry only, charged under2^40 fixed work; no target search is hidden in code.
Only a fixed small register set is live. No terminal key/index slabs, entire
orbit, collision advice or uncharged key registers are retained.

12. Provenance and limits. This directly builds on branch-coded lookup submission
18bc6884-1b43-455d-9291-6ffa2ab062b4. It retains that construction, lookup,
recovery, success premise and finite probes. Section 15 replaces repeated
invariant-argument assignment with a persistent read-only descriptor, reducing
the adapter from twelve to four operations and the controller from 32 to 24. Its prior packages are
b2bf3e7c-6c73-45c7-bda7-bb4b8b9efae4 (equality fetch),
2dcaeba6-0dfc-432f-a886-2cba1ce6e8a3 (variable height),
df041842-52c4-4bdd-9a6d-d81001ea734d (root cache), and
eb7fbf7c-e57c-407b-a79d-a644516edce1 (aligned cap).
The full target, salted
injection, cap, H-cap511 premise, sufficient event, recovery and finite probe
source are inherited. The sole new feature is section15 persistent-descriptor adapter; section10 branch-coded literal-address lookup is inherited. Its result
is unchanged; orbit behavior, sufficient event and heuristics are retained. Earlier historical provenance includes
f1757b87-5434-43f8-99b5-cff099ef2a14 and salted rho work
6f55e9bf-8eb5-49e5-b37c-0d379ddbe883. Historical names do not assert
verified attribution edges or human decisions. All mathematics needed for
review is included here. The finite probes retain sorted search and do not
execute the branch-coded lookup or validate this RAM instruction count. Their
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

14. Equality-only terminal fetch bound. The program in section 10
returns NONE before the terminal-index fetch when its lower-bound key differs
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
If k>=m, since m=511D is an integer multiple of D and D<m, we have mu>m-D.
All cycle-state queries then lie in an interval of length less than
B-(m-D)=2D. There are at most 2D+1 U-state queries. Combining all cases,
2D+2 is a conservative uniform bound on U-state queries in detection.

Each such query needs at most one equality fetch, and there is at most one
non-U terminating fetch. Thus the fetch count is at most 2D+3 on every orbit,
not merely on E or typical random mappings. The resulting search bound is
13315D+3, yielding the ledger in section 10. The inherited branch-coded lookup supplies the same indices, with the same success
event and heuristic. No finite probe is changed. The tighter time exponent
128.11824544020126 is conservatively rounded to 128.119; the positive slack
exceeds 2^108 target units and covers fixed work below 2^31. This is deterministic
accounting, not a claim that key matches are probabilistically rare.

15. Explicit detection controller and adapter. This revision replaces the predecessor
32-operation nonsearch allowance with a concrete at-most-24 body.
Use global word registers for x,j,k,z, constants and argument pointers. No host
ABI, stack saving, per-query phase dispatch or subword index conversion is used.
The selected phase body contains its own inline fixed-height lookup from
section 10. Key mismatch jumps directly to MISS; a terminal fetch obtains k.
The empty phase jumps directly to MISS. The only other detection paths are:

    LOOP:
        target_adapter()             # 4 word operations, plus H target call
        j = j + 1                    # 1
        inline_phase_lookup(x)       # charged separately in section 10
        if k != NONE: goto RECOVER   # part of 8 routing allowance
        goto MISS                    # part of 8 routing allowance
    MISS:
        if j == B: goto FAILURE      # comparison + branch: 2
        z = j & (D-1)                # AND: 1
        if z != 0: goto LOOP         # comparison + branch: 2
        if j >= m: goto LOOP         # comparison + branch: 2
        goto INSERT                  # branch: 1
    INSERT:
        append_and_rebuild()          # all insertion/phase work fixed-priced
        goto selected_phase_LOOP     # phase transfer in fixed allowance

RECOVER is exactly section 4's bounded terminating routine, with its unchanged
128-operation allowance per recovery target call. FAILURE terminates. No state
is skipped: j starts at zero, target_adapter updates x=f_S(x), and j increments
before the lookup, exactly matching section 4. All masks are literal 256-bit
word constants initialized once; D=2^119 makes mod D the shown AND.

The adapter uses a persistent descriptor for the exact selected compression.
Initialize once: message pointer to two 256-bit words, standard IV pointer,
counter zero, true block length 64, flags 11, rounds 3 and output pointer.
Store S once in the first message word. These constants and argument registers
remain unchanged across detection calls. Compression has a private workspace,
separate from its read-only descriptor, the lookup registers and orbit registers.
It writes only its designated output buffer. No calling convention requires
callee-clobbering the descriptor; this is an explicitly chosen word-RAM program.
The only changing input is the second message word, x. Each call performs:

    STORE_LITERAL(message_second_word, x)   # 1 store
    CALL selected_compression              # 1 control transfer, plus H=1
    RETURN_FROM_COMPRESSION                # 1 control transfer
    x = LOAD_LITERAL(output_first_word)    # 1 load

The return is charged here, rather than hidden inside the compression price.
Literal addresses are fixed code operands as in section 10. The full internal
compression remains priced at one selected-target unit, with no discount for
its invariant arguments. Read-only arguments are reused, never changed into a
free-start IV or nonstandard flags. Loading them internally is covered by the
same complete reference compression price used in the predecessor. Message and
output buffers use the specified little-endian word representation; no endian
conversion or intermediate message copy is needed. Initialize the descriptor
and salt for at most 32 fixed word operations within the 2^40 allowance.
Recovery may overwrite its own descriptor, but is terminal: detection never
resumes after recovery. It retains the old 128-operation allowance per call.
The persistent descriptor needs at most eight words, within the existing 8192
byte workspace. All register contents and code are counted in memory.

In addition to adapter4, reserve8 for all search-result/NONE/hit routing,
including k!=NONE comparison+branch (2), miss transfer (1), optional NONE
assignment (1), final-failure transfer (1), and three spare transfer operations.
Key equality comparison and branch and terminal fetch remain in search work,
never removed. Add counter increment1; cap comparison+branch2; checkpoint
mask and comparison+branch3; j>=m comparison+branch2; insertion/continuation
transfers2; and two spare register/pointer moves2. Total4+8+1+2+3+2+2+2=24.
Some paths use fewer operations; every detection query is charged all24.
Appending, rebuilding, selecting the next phase body and refreshing the root
are already included in the fixed 2^40 allowance, not omitted. Recovery is not
charged at this lower rate. All comparisons and branches use the priced RAM
primitives. The ten uniform phase bodies and shared routines remain within
section 11's code reservation. No data-dependent code generation is needed.

The 24-operation controller combined with the inherited lookup gives
W<=25987D+259+2^40. With H<=515D+2 and C=638 the leading exponent is
128.11824544020126, conservatively rounded upward to128.119. The rounding
slack exceeds2^108 target units and dominates all fixed charges. This is a
controller implementation/resource refinement; it does not strengthen the
success heuristic, change the finite probes, or claim a full-width experiment.
