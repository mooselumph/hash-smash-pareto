# Sparse-checkpoint salted rho for complete BLAKE3-r3

1. Scope and result. This is a classical ordinary collision construction for
complete unkeyed BLAKE3 with prefix rounds 0,1,2 in every compression. It uses
one explicit fixed-target heuristic H-cap511. Conditional on that premise,
its success probability is at least 0.39. Its deterministic total work is below
2^128.225 selected-target compression units, including failures, and all memory
is at most 2^20 bytes. Consequently its normalized time-memory cost is 128.225.
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
record uses two 32-byte RAM words. Maintain two separate one-word Eytzinger arrays K and J, each with slots
0..511. Their occupied heap indices 1..511 form a perfect depth-9 tree.
Assign the n real sorted records first in inorder, followed by 511-n padding
records with key U=2^256-1 and index NONE. A real key U precedes all padding.
K holds keys and J holds orbit indices. Rebuild after every insertion.
Section 10 specifies a lower-bound lookup that returns the unique real exact
match or NONE, even for key U. Insert sorted records by shifting in place.
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
have D_n=1: every projected state is a checkpoint. Apply the same checkpoint
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
using the same controller, sorted arrays and output predicates. Their spacing
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

10. Deterministic total-work ledger and exact lookup. C=638 word operations
per selected target compression. Detection uses at most m+D target calls;
right reconstruction fewer than D; synchronous recovery at most 2D; final
verification at most two. Thus H<=m+4D+2 for every random choice and failure.
There are at most 510 searchable real checkpoint records, at positive
multiples D strictly below m. The chronological array additionally retains x0.
Padding fills the perfect tree to 511 nodes. No later checkpoint is inserted.

Allocate K at absolute word addresses 0..511 in the word RAM; code, registers,
J, L, R and all other arrays occupy disjoint addresses beyond this interval.
The unused K[0] is an ordinary allocated word, not a host null pointer.
LOAD(i) reads exactly one 256-bit word at word address i; it is the priced
RAM load primitive, with no hidden indexing or scaled addressing.
This is an abstract word-RAM layout, not a claim about host-language pointers.
After each rebuild, cache K[1] in register root_key, charging its load and
assignment to the fixed rebuild allowance. Initialize this register after the
initial padding build as well. It remains unchanged until the next insertion.
For each lookup first execute these two operations:

    b = (root_key < x)
    i = 2 + b

These are exactly the first descent edge with its constant index folded.
Then execute the following four operations exactly eight times, with eight
explicit straight-line copies, so no loop test or jump:

    y = LOAD(i)
    b = (y < x)                 # comparison returns word 0 or 1
    i = i << 1
    i = i + b

The resulting external-leaf index is in [512,1023]. Each left edge means the
parent key was >=x; each right edge means it was <x. The deepest ancestor from
which the path took a left edge is the inorder lower bound, if one exists.
Delete all terminal right edges and the preceding left edge to obtain it.
For an all-right path the answer is index zero, meaning no lower bound.
Use two direct terminal tables L and R. L occupies absolute word addresses
512..1023; R occupies 1024..1535. For each external leaf u, compute
its last-left ancestor a=u>>(t(u)+1), with t(u) the trailing-one count,
including a=0 for u=1023. If a=0, set L[u]=U and R[u+512]=NONE.
Otherwise set L[u]=K[a] and R[u+512]=J[a]. These are copies of the
current lower-bound record, rebuilt after each checkpoint insertion, never
advice or a precomputed collision. All arrays occupy disjoint intervals.
After the specialized first edge and eight descent copies, execute:

    y = LOAD(i)
    if y != x: return NONE
    k = LOAD(i+512)
    return k

The conditional costs a comparison and branch. For no lower bound the
sentinel pair (U,NONE) returns NONE even if x=U. Padding likewise returns
NONE. A real key U precedes padding and is selected correctly.
The first edge costs two, remaining descent 32, terminal key load one, equality
check two, index address and load two: at most 39 operations. Charge 39 operations. Return routing remains in the64 controller allowance.
Table generation traverses at most10 bits per512 leaves and copies at most
two words each; an extra256 operations per leaf per rebuild suffices.

Correctness: along the search path all keys passed by a right edge are <x and
cannot be a lower bound. A key passed by a left edge is a candidate >=x, and
each later left edge supplies a candidate earlier in inorder. Hence the last
left parent is the first inorder key >=x. A real exact key, including U, occurs
before any equal padding, so if an exact real key exists this first key is real
and J returns its index. If the lower bound is padding, J returns NONE; if its
key is greater than x, the equality check returns NONE. The all-right case also
returns NONE. Therefore lookup is extensionally identical to the inherited exact
sorted search, with no additional heuristic or failure event.

Add the inherited 64-operation nonsearch controller allowance from section 13:
39+64=103. Charge 103 noncompression operations per detection call.
Recovery retains a separate 128-operation allowance per target call. No native multiplication,
ctz instruction, conditional move or unpriced table access is assumed.

Each sorted insertion shifts at most 511 two-word records, at 32 operations
per record plus 512 setup/append operations. Rebuild traverses all 511 nodes
inorder with an explicit stack of at most 14 two-word frames. Copy the next
real sorted record if available, otherwise write literal (U,NONE). At most
256 operations per node covers traversal, addresses, tests, both stores and
stack maintenance. Across at most 512 rebuilds the bound is
    512*(32*511+512+256*511+256*512) < 2^32 word operations.
The fixed allowance 2^40 covers this, initialization, two uniform random words,
output, final verification adapters and finite preliminary research. Thus
    W <=103*(m+D)+128*(3D+2)+2^40,
    T <= m+4D+2 + (103*(m+D)+128*(3D+2)+2^40)/638.
Writing Q=2^128, the leading coefficient on Q is
    511/512+4/512+(103*(511/512+1/512)+384/512)/638,
whose logarithm is 0.224629251. The claimed 128.225 leaves positive slack
for the additive fixed charges. The separate recovery rate avoids undercharging
its unchanged 128-operation allowance. No recovery is charged at the lower
103-operation detection rate.
All trials and failures are charged; there are no restarts. This is total work,
not wall time. The fixed allowance in compression units is below 2^31.

11. Memory ledger. Chronological checkpoints use 512*32=16384 bytes;
sorted two-word records use 511*64=32704 bytes. K and J each have 512 slots,
including unused index zero: together 2*512*32=32768 bytes. Sum: 81856 bytes.
Reserve 65536 bytes for uniform code/constants and 8192 for live words,
compression workspace, buffers and the at-most-14-frame rebuild stack. The
two terminal arrays add 32768 bytes. Total 188352 bytes, below 1048576.
The two first-edge operations and eight four-operation descent copies fit the code reserve. The root_key register fits within the 8192-byte workspace reserve. Rebuild reads
sorted records and writes K,J without extra arrays. Insertions use temporary
words in the workspace. No advice or retained full orbit is stored. The claimed
memory_log2_bytes=20 is conservative and adds zero memory penalty.

12. Provenance and revision. This work directly retains from
6f55e9bf-8eb5-49e5-b37c-0d379ddbe883 the complete 64-byte root specialization,
salted state injection, fixed-target heuristic framing, random-mapping argument,
finite root-probe implementation and compression-based resource accounting.
Historically the cap m=2^128 was explored in submission
1062e941-1aa2-42fd-ad11-f75feea550fc, whose score is not presumed here.
The sparse-checkpoint detection and bounded local recovery replace Floyd's
three-evaluation detection and full-tail recovery. This is generic orbit search,
not a new BLAKE3 differential. Earlier methods supply context and attribution;
this package supplies all mathematics needed without fetching outside papers.
The new cycle-length restriction, sparse table memory and binary-search costs
are explicit. The lower cost is conditional on H-cap511 and is not an
unconditional improvement of earlier nonheuristic collision bounds. Official
execution, AI review, human publication and promotion are distinct outcomes.

13. Nonsearch control allowance and provenance. Historical provenance includes
f3058579-d6b9-49a5-9a09-3ea0b11cca0a, which builds on
473f2d01-7012-45be-89f9-3f350b6ecf75. It retains the exact complete target,
salt injection, orbit controller, random-map reasoning, recovery and all four
experiment parameters and source bytes. Sparse-probe manifest prose is updated
historically to identify spacing1/512; this revision uses1/511. The sufficient event and full-width premise
are strengthened by the new spacing, as explicitly stated in sections6 and14. The predecessor in turn builds on aebd6cd3-a42e-4762-94f9-4559a7badedb,
f6a36631-f9ca-4652-ac44-1fdb24d23dcb and earlier work attributed in section 12.
The inherited 64-operation detection allowance is retained: 12 for input/output
buffers and target argument setup; 8 for orbit counter, cap and loop routing;
8 for checkpoint-mask tests including the j<m guard; 12 for search return and NONE/hit routing;
8 for pointer/register updates and count access; 16 for literals, addressing
and control transfers. Lookup initialization, addresses, key comparisons,
index decoding and J loads are already charged explicitly in section 10.
39+64=103 for detection. Recovery separately retains 128 operations.
The compression primitive internals are charged by H, never discounted.
Insertion, padding and rebuilding are separately charged to fixed work.

The finite probes retain sorted lookup. Section 10 proves identical returned
indices for the new padded lower-bound tree, including equality at the largest
word and padding. For any common searchable set this lookup behavior is identical. The inherited
probes retain the old endpoint records, so they do not execute the new pruning
or measure or empirically verify the new RAM instruction count. No local
experiment result or full-width execution is asserted. This is a deterministic
resource improvement conditional on the explicitly strengthened unresolved heuristic;
it supplies no new differential, full-width evidence or human acceptance.

14. Aligned-cap revision and direct provenance. This revision directly uses
f1757b87-5434-43f8-99b5-cff099ef2a14: its complete salted target, controller,
terminal lookup, cost allowances, finite probe source and proof. The cap is
reduced from 512*D to 511*D, with D=2^119 unchanged. This makes B=2^128
and removes the last searchable checkpoint. Arrays keep their former reserved
capacities; the perfect depth-nine tree and padding are unchanged. Since m
remains an integer multiple of D, all ceiling and recovery arguments in
section 5 remain valid. No new operation or failure path is introduced.

The full-width event is strictly smaller than the predecessor event, so the
new H-cap511 is a strengthened unresolved premise. Prior qualification does
not establish it. Its independent random-map lower bound exceeds 0.3903354,
which is above 0.39 but has less margin than the predecessor. The finite
12/16-bit probes are byte-identical and keep their original caps and spacing;
they neither execute the changed cap nor establish its full-width success
probability. They remain only limited evidence about the generic controller
and exact root implementation. There is no asserted new observation.

The work exponent from the explicit finite ledger is 128.22462925016123 plus
a negligible positive fixed term, conservatively rounded upward to 128.225.
The additive term is below 2^31 target units, whereas the rounding slack is
greater than 2^116 target units. Memory capacities are deliberately unchanged,
so 188352 bytes and the conservative 2^20-byte claim remain valid. This is a
small conditional resource improvement, not a new differential or unconditional
collision bound. No human acceptance or promotion is asserted.

15. Cached-root specialization and direct dependency. This revision directly
builds on eb7fbf7c-e57c-407b-a79d-a644516edce1. It retains its exact full target,
H-cap511 premise, sufficient event, recovery, parameters, probe bytes and memory
reservations. The sole new optimization is the root specialization in section 10.
At the start of each lookup i was the literal 1. LOAD(1) always read K[1],
which changes only when the search tree is rebuilt. Keep that value in a
register across queries. The original first edge (initialize i, load K[i],
compare, shift i, add b) costs five operations; the specialized compare and
literal addition cost two. For either comparison result the next i is exactly
the same integer 2+b. The remaining eight edges and terminal lookup are identical,
so returned indices and success events are identical for every orbit, including
sentinel cases. No extra distributional premise is introduced.
The extra root refresh costs at most two operations per rebuild, fewer than
1024 operations in all, absorbed in the existing enormous 2^40 fixed allowance.
A register is already reserved in the workspace. The probes still implement
sorted search; they do not measure this RAM optimization. The submitted bound
128.225 exceeds the leading exponent 128.22462925016123 with slack greater than
2^115 target units, covering all fixed work. This is a conditional resource
improvement; no new full-width evidence, human acceptance or promotion is claimed.
