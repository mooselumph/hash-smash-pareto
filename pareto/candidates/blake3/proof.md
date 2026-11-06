# Four-wise independent message regeneration for complete BLAKE3-r3

1. Scope and sources. This is an unconditional generic finite construction in
the stipulated classical word RAM, not practical reduced-round cryptanalysis.
It improves storage by regenerating 64-byte messages from four random field
coefficients instead of retaining all messages. Four-wise independence replaces
full independence within each batch; a second-moment argument replaces the old
elementary-symmetric-polynomial argument. Independent batches are retained.
The direct starting source is submission e2b9c62e-caf8-413f-a57b-d7623015010d.
This revision introduces scheduled lower-index-only derivative updates,
proved in section 5 and charged by an aggregate finite count. This revision
also streams packed output words and caches the two current merge heads,
with the complete aggregate cursor/output ledger in section 9. It additionally terminates the entire attack after the first digest-repeat
recovery, even if that recovery finds only identical messages. Thus at most one
regeneration pass is charged globally rather than once in every batch.
The raw time claim is 242.30, memory 20, success probability 0.39. This does not
beat the nominal security exponent 128. No executed collision is claimed.
Material public predecessors are c0caf02f-5719-4cd7-bdd6-4fe2772b4d82
(bounded-memory batching and fixed-target formulation),
9d85b4bf-faeb-45b3-82e6-abcd3f9ef054 (packed indices),
297cb249-5af2-4a8c-a7e6-94cd85d579a0 (bottom-up index merging), and
e98e233a-5661-48b9-835f-d8c943d6009d (explicit message-domain and duplicate
probability accounting). These are source attributions, not human acceptance.
The self-contained construction and argument follow.

2. Exact target. F maps 64-byte strings to all 32 output bytes of the standard
unkeyed complete BLAKE3 hash with rounds 0,1,2 in every compression. Preserve
IV, initialization, G, message permutation and feed-forward. For these one-block
messages the complete root hash uses IV as input CV, actual length 64, counter
zero, flags CHUNK_START|CHUNK_END|ROOT=11. Return the first eight little-endian
output words. No separate chunk-CV compression is needed for the single final
root block. Thus each F call costs exactly one selected compression. No parent,
intermediate CV or partial digest is substituted. All 512-bit messages satisfy
the required byte-string domain and length bound.

3. Field and uniform parameters. Use K=F2[X]/h(X),
h=X^512+X^8+X^5+X^2+1, and the usual polynomial basis. It is an irreducible
binary pentanomial: the entry for degree 512 in Gadiel Seroussi's primary table
HPL-98-135, August 1998, appendix printed page 4, is (512,8,5,2), meaning the
four nonconstant exponents with constant term one. Source:
https://shiftleft.com/mirrors/www.hpl.hp.com/techreports/98/HPL-98-135.pdf
Only this single finite algebraic fact is used from the table. For reproducible
verification without fetching the paper, the exact irreducibility test is:
start r=X; repeat 256 times r=(r*r) mod h in F2[X]; check gcd(r+X,h)=1;
repeat a further 256 squarings modulo h and check r=X. Both checks pass for the
specified h. These checks suffice because the only prime divisor of 512 is 2:
the second condition makes h a squarefree divisor of X^(2^512)-X, whose
irreducible factors have degrees dividing 512; the first excludes every degree
dividing 256, hence excludes every proper divisor. The algorithm may perform
this deterministic one-time verification as part of its setup. It is not a
heuristic about BLAKE3 and no experiment report is asserted.
Represent a field element by two 256-bit words containing its coefficients,
low degrees first. This is also its complete 64-byte message serialization.
Set q=26864, k=15, N=2^256, D=q(q-1),
R=ceil(124*N/(125*D)). All q indices fit in 16 bits and q<2^15.

4. Four-wise family. In each batch independently sample four independent
uniform field elements a0,a1,a2,a3 (eight independent uniform RAM word draws).
Define P(z)=a0+a1*z+a2*z^2+a3*z^3 over K. For each j=0,...,q-1 let
x(j)=j XOR (j>>1), interpreted as a polynomial of degree at most 14.
The x(j) are distinct. The message at j is P(x(j)) serialized to 64 bytes.
Any at most four distinct messages are independent and uniform over K: the
Vandermonde evaluation map from the four coefficients to evaluations at four
distinct field points is invertible, with determinant the nonzero product of
point differences. Marginalizing gives the smaller cases. This statement is
about the actual independent coefficients, not a pseudorandom generator or
seed-expansion hypothesis. Full independence of all q messages is not claimed.

5. Cheap Gray-code generation. Write ei=X^i, i=0,...,14. In characteristic two,
P(sum xi*ei)=a0+sum Bi*xi+sum_(i<j) Cij*xi*xj, where
Bi=a1*X^i+a2*X^(2i)+a3*X^(3i),
Cij=a3*X^(i+2j)+a3*X^(j+2i), and Cii=0, Cji=Cij.
All field additions are bitwise XOR of the two words. Prepare arrays
S1[t]=a1*X^t (0<=t<=14), S2[t]=a2*X^t (0<=t<=28), and
S3[t]=a3*X^t (0<=t<=42) by repeated multiplication by X modulo h.
One such step shifts the two-word vector left once; if old bit 511 is set,
XOR low-word mask 0x125 (bits 8,5,2,0). Cross-word carry uses old low bit255.
This takes at most 16 word operations with register temporaries and branch.
No general finite-field multiplication is needed during generation or setup
of the per-batch coefficient arrays. Use the displayed S entries to fill B
and the full 15-by-15 symmetric matrix C. Only 84 successive X steps and 225
short XOR/lookup constructions are required.
Use scheduled derivatives rather than updating all fifteen on every step.
Define E0=B0 and Ei=Bi XOR C[i,i-1] for i=1,...,14.
Maintain Ui=Ei XOR sum_(j>i) Cij*xj. Initially x=0, v=a0, Ui=Ei.
For transition n=j+1 (1<=n<q), let i=ctz(n). Update v <- v XOR Ui;
then update Uh <- Uh XOR Chi for h=0,...,i-1 ONLY. Toggle bit i of x.
No higher derivative is touched. These updates maintain the displayed U
invariant because only a bit higher than h can change its defining sum.
At a transition with ctz(n)=i, the old Gray value x=(n-1) XOR ((n-1)>>1)
has lower coordinates x[i-1]=1 for i>0 and x[h]=0 for h<i-1.
Indeed n-1 ends in i ones and its bit i is zero; XOR with its shift
cancels all but the highest of those trailing ones. For i=0 there are
no lower coordinates. The bit-i finite difference of P at this x is
Bi XOR sum_(h!=i) Cih*xh = Ei XOR sum_(h>i) Cih*xh = Ui.
Thus the v update is exact, even though Ui is not the full derivative
at arbitrary unscheduled states. Induction proves v=P(x) at every output.
The point sequence, uniform coefficients and four-wise independence are unchanged.
Compute ctz with explicit low-bit tests and shifts, not a primitive ctz.
The total number of lower-derivative updates over q-1 transitions is
sum_(n=1)^(q-1) ctz(n) = sum_(t>=1) floor((q-1)/2^t) < q.
Hence fewer than q two-word derivative updates suffice for the entire batch,
in place of fifteen per message. No transition follows the last output.

6. Batch algorithm. Allocate q digest words only; messages are not stored.
Generate v for each j as above, compute F(v), and store digest[j].
Do not initialize packed index arrays. Sort each full consecutive group of
sixteen digest words in registers, carrying its sixteen absolute indices.
The sorting network S16 consists of S8 on positions 0..7, S8 on positions
8..15, then the 25-comparator merge M16 defined below. S8 is this exact
19-comparator sequence:
(0,1),(2,3),(0,2),(1,3),(1,2),
(4,5),(6,7),(4,6),(5,7),(5,6),
(0,4),(2,6),(2,4),(1,5),(3,7),(3,5),(1,2),(3,4),(5,6).
For a merge of n total strided entries with two sorted halves, define the
compile-time schedule M(lo,n,r): if 2r<n, emit M(lo,n,2r), then M(lo+r,n,2r),
then comparisons (i,i+r) for i=lo+r,lo+3r,... with i+r<lo+n; otherwise emit
(lo,lo+r). M16 means M(0,16,1). All schedules are expanded into fixed code;
there is no runtime recursion, schedule generation or table lookup.
M16 uses two nine-comparator eight-entry merges plus seven boundary comparisons,
so S16 has 2*19+25=63 comparators. A comparator swaps both key and index iff
its left key is greater. Pack the sixteen 16-bit sorted indices into a single
256-bit word and store it directly to packed array A. There are exactly 1679 full groups and no tail.
No sentinel value or padding key is introduced. Continue ordinary
bottom-up merges at widths 16,32,...,16384, using two packed 16-bit buffers A,B.
Merge adjacent sorted runs into the other buffer, using the left input on ties,
avoiding reads from exhausted runs, and swap bases after each full pass.
For each merge cache the two current indices and their digest keys.
Initialize a head only for a nonempty run. Emit the lesser head, then advance
and refresh only that source head if not exhausted. Cache the other head.
For output maintain a 256-bit accumulator and a bit offset starting at zero
once per entire pass. Append each 16-bit index by shift/OR, advance the bit
offset by 16, and when it reaches 256 store the full accumulator to the next
destination word and reset it and the offset. Continue across merge boundaries.
After the pass store a final partial word if present; unused cells are zero.
This exactly implements the same packed array, with no per-cell destination
read-modify-write. The initial networks and eleven logical merge passes suffice. The first ten
passes write packed indices normally. In the final pass (width 16384), do not
write destination indices. Instead consume the sorted head-key stream, keeping
one previous digest key. The first output initializes that key. Each later key
is compared with the previous key; if equal, retain the current original index
as representative and its digest, then begin recovery immediately. Otherwise
replace the previous key and continue. If the final stream ends without a
repeat, this batch fails. Thus no final packed output or subsequent scan is
needed. A boolean final-pass flag selects output packing versus monitoring,
with explicit per-output compare/branch cost charged in section 9.

7. Bounded recovery. Regenerate the retained representative
message P(x(s)) once by direct Horner evaluation. Then regenerate all q messages
in a single Gray-order pass using retained E,C and original a0, resetting U=E.
Compare each message whose stored digest equals the chosen digest with the
representative. If they differ, verify both complete hashes and return the pair.
Otherwise, after the single pass terminate THE ENTIRE ATTACK with failure,
without examining other runs or batches. After at most R batches without any
digest repeat, return failure. No extra table,
per-run message store, or multiple regeneration passes are used.
If a batch contains a digest repeat and contains NO identical-message pair,
its first repeated-digest run necessarily yields a valid collision. Therefore
we may subtract the event of any identical-message pair from the event of any
digest repeat. This remains valid for global early termination: outside the
subtracted bad event the first repeat anywhere must succeed, so no later
batch can be lost to unsuccessful recovery. The conservative event is exactly
the probability proof below.
Sorting correctness follows by induction on the merged run width: every index
appears once and each merged run is ordered. Consequently no equal-digest run
is missed by final-stream monitoring, and only distinct full-message equality is accepted.

8. Fixed-target second moment. For independent uniform single messages write
p_y=Pr[F(M)=y], p2=sum p_y^2, p3=sum p_y^3. Regardless of this fixed function,
p2>=1/N by Cauchy-Schwarz and p3<=p2^(3/2) by the monotonicity of finite l_p
norms. Let Z count digest-equal unordered pairs among q generated messages.
Four-wise independence gives the EXACT moments
lambda=E[Z]=D*p2/2,
E[Z^2]=lambda+6*choose(q,3)*p3+6*choose(q,4)*p2^2.
Terms correspond to identical pairs, pairs sharing one index, and disjoint
pairs; no higher independence is used. At q=26864,
6*choose(q,3)*p3 <= q^3*p2^(3/2) < 3*lambda^(3/2),
since (2*q/(q-1))^(3/2)<3. Also
6*choose(q,4)*p2^2 <= lambda^2.
Cauchy-Schwarz applied to Z*1_(Z>0) therefore gives
Pr[Z>0] >= lambda/(1+3*sqrt(lambda)+lambda).
This function is increasing for lambda>=0: differentiating gives a numerator
1+(3/2)*sqrt(lambda)>0. With lambda0=D/(2N), it follows that
Pr[Z>0] >= lambda0/(1+3*sqrt(lambda0)+lambda0) > 0.999*lambda0.
The last strict inequality holds since lambda0<2^-226.
Fresh coefficient sets make different batches independent. Thus over R batches,
Pr[at least one digest repeat] >= 1-exp(-0.999*R*D/(2N))
>= 1-exp(-0.495504) > 0.39073.
Each message pair is independently uniform over 512 bits, so a union bound over
all within-batch identical-message pairs is at most
R*D/(2*2^512) <= 0.992*2^-257+D/2^513 < 2^-256.
Outside this bad event, the first repeated-digest run recovery always succeeds.
Subtracting gives success greater than 0.39073-2^-256 > 0.39.
This argument is distribution-free for F. It does not assume independent outputs
when inputs are dependent beyond four-wise, ideal mixing, or a random mapping.

9. Charged batch work. C=638 is the selected-round normalization. Every random
draw, load/store, address calculation, XOR, shift, mask, branch and counter is
charged. All quoted bounds concern primitive word operations, with no field,
ctz, multiplication, library-sort or Gray-generator instruction silently free.
Cache a packed source word for each merge input, alongside its existing
cached head and digest key. Each source cursor holds a shifted word V, the
number r of valid low-end cells remaining, and a pointer to its next packed
word. To get an index: if r=0, load the next word, advance the pointer by 32,
and set r=16; then extract V AND 65535, shift V right16, and decrement r.
The test costs comparison plus branch (2), extraction/shift/decrement costs 3,
and each word refill costs 3. At the widths used here (16,32,...,16384), all
source starts and lengths are multiples of16 because q=26864 is too. Thus
there are exactly q/16 source words over both inputs of one full pass, with
no alignment fragments. Charging refills for ALL these words, not just the
ones beyond initial cached heads, gives at most 5q+3q/16 source-read operations.
Digest dereferencing still costs at most 5 per consumed source index, including
address arithmetic. Head/key refresh therefore totals at most
(10+3/16)q < 11q over an entire pass. This is a deterministic aggregate count;
no statistical or amortized-over-unbounded-input assumption is used. Initial
head/key handling is also retained within the96-operation run setup budget,
which covers initializing the two cursor states. At most one source advances
after each selected key, and no exhausted source reads beyond its run.
Use the safe per-pass refresh allowance 11q instead of the old 14q.
A streamed output index uses at most 11 operations: shift index by bit offset,
OR into accumulator, add 16 to offset, compare and branch, and in the flush
case store accumulator, advance destination pointer, clear accumulator and
offset. Nine operations suffice on a flush iteration; eleven includes register
moves and remaining control. No destination word is read. The final partial
flush is fixed pass work charged in the 65536 allowance.
Comparison/selection contributes at most 4 operations; source increment,
exhaustion tests, head-valid state, output count and loop control at most 16.
Therefore aggregate ordinary output work is at most
(11+11+4+16)q=42q per full pass.
This revision uses a deterministic aggregate cursor bound; all writer,
selection and ordinary loop-control allowances remain charged.
Exhausted-run iterations avoid refreshing invalid heads and fit the same cap.
Run initialization costs at most 96 operations: boundary minima and address
setup, two initial source index/key reads at at most 28, setting head-valid
flags and counters and loop control. This increases the preceding run allowance
from 64 to 96 to pay explicitly for cached head initialization.
The normal merge core includes a final-pass flag test on each logical output:
one comparison and one conditional branch, charged as TWO operations beyond
the preceding 42q ordinary per-pass ledger. Hence ten materialized passes cost
at most 10*44q. For the last pass, omit the 11-operation streamed packed writer
and substitute at most four operations to compare the cached selected key with
the previous key, branch on equality, and update the previous-key register.
Its cost is at most (42-11+4+2)q=37q. The first key is consumed in a separate prologue before the monitoring loop,
so there is no per-key first-output test. The prologue and selected representative
use fixed setup work; all source refresh, exhaustion and loop costs remain.
The code addition uses at most sixteen instructions for flag routing, previous
key handling and the match exit; it is included in the extra code budget below.
There are exactly 11q logical merge outputs. The number of ordinary runs is
sum_(w=16,32,...,16384) ceil(q/(2w)) < q/16+11. Thus 6q plus the fixed
65536 allowance covers ordinary run setups, swaps and final partial stores.
Each sixteen-element group costs at most 640 operations, or 40 per entry:
63 compare-exchanges at at most 8 operations each (comparison, skip branch,
three register moves for each of key and index) = 504; sixteen consecutive
key loads and pointer increments at most 32; forming sixteen absolute indices
at most 16; packing them at most 30 (fifteen shifts and fifteen ORs);
output store and pointer advance at most 4; advancing j and group loop at
most 4. The sum is 590, leaving 50 operations for remaining selection/control.
There is no tail. All q entries therefore fit 40q. No schedule interpreter
or source-index reads are used. Thirty-two word registers occupy 1024 bytes
inside existing scratch. Initial pointers fit the fixed allowance.

Network correctness is analytic. The five-comparator S4 prefix sorts four
inputs by sorting two pairs, comparing their minima and maxima, then comparing
the middle two. The nine-comparator S8 suffix merges the two sorted S4 outputs
by merging their even subsequences, their odd subsequences, then repairing
adjacent odd/even boundaries. M16 uses exactly the same recursive merge.
For its general correctness on binary inputs, suppose two sorted halves have
a and b zeros. The merged even subsequences have e=ceil(a/2)+ceil(b/2) zeros;
the merged odd subsequences have o=floor(a/2)+floor(b/2) zeros. Thus e-o is
0,1 or 2. Their interleave is sorted when e=o or e=o+1. If e=o+2, exactly one
inverted adjacent pair occurs at positions (2o+1,2o+2), among the scheduled
odd/even boundary repairs. The base merge of two singletons is a comparator.
Induction proves M16 merges binary sorted halves. Thresholding commutes with
comparisons: an inversion among arbitrary keys would produce an inversion on
binary keys using a threshold between them. This proves S8 and S16 for all
256-bit keys and ties. Carrying indices gives a permutation. The sorted full groups establish the induction base for eleven ordinary merge passes.

Generation uses at most 128q auxiliary operations for the whole batch.
One lower-derivative update costs at most 16 operations as in the predecessor:
load its two C words and two U words, XOR two words, store two words,
advance both pointers, and control the loop. There are fewer than q such
updates globally, contributing at most 16q. Finding ctz by low-bit tests,
shifts and a loop takes at most 8*(1+ctz(n)) per transition, hence less
than 16q in aggregate. Loading Ui, updating v and deriving row pointers
costs at most 24 per transition, hence 24q. The remaining 72q covers
compression input setup (IV, length, flags, counter, message serialization),
digest store, packed index initialization, x and n updates and outer loop
control; each packed index write costs at most 16 and digest store/address
at most 4, leaving 52 for the stated short fixed sequences. Eight fresh
random coefficient words and E and U initialization fit the fixed batch allowance.
Unlike a per-message worst-case estimate, this is a deterministic aggregate
bound: the exact sum of trailing-zero counts controls all iterations.
The regeneration pass costs at most 416q operations: a conservative at-most-384
aggregate operations per regenerated message using the same scheduled generator, plus 32 for loading/looking up its stored digest,
comparison with the chosen digest, full two-word message comparison and loop
control. It needs no q additional compressions: stored digest[j] is exact,
and final verification is separately charged once on successful recovery.
Only one regeneration pass is ever executed over the entire attack, because
any repeat triggers global termination after recovery. Charge its 416q
operations once in section 10, instead of to every batch.
There is no post-sort scan. The final logical merge stream is sorted by the
same head-selection induction as a stored merge. Every equal-key run has two
consecutive stream entries, so monitoring misses no digest repeat. Retaining
one original index provides the representative required by recovery, even if
the stream is stopped before its remaining entries are consumed. The intact
original digest[j] array supports the recovery pass without final sorted data.

Per-batch fixed work is at most 65536 operations: prepare shifted-coefficient
arrays and C,B (under 16384 operations, using 84 X steps and 225 short
constructions), sample coefficients, initialize/reset U and v, pass swaps and
extra run setups, choose the first repeated digest, and regenerate its one
representative. For the latter, x is a polynomial with at most 15 coefficients,
so multiplying a field element by x is done in at most 15 shift/reduction and
conditional-XOR iterations, under 512 operations. Horner evaluation uses three
such products and three XORs; 4096 operations comfortably suffice. Coefficients
and tables are freshly rebuilt in EVERY batch; no independent-batch setup is
amortized away. Shifted S arrays may be overwritten after C,B preparation.
Thus
W_batch <= (10*44+37+40+6+128)*q+65536
        = 651*q+65536 = 17554000 auxiliary operations.
All failed batches, fresh coins, sorting, initialization, recovery and traffic
are included. There is no full-message retention or copying during sorting.

10. Total finite time. One-time setup and buffer initialization use at most
2^40 word operations, including the optional finite irreducibility test in
section 3. Polynomial multiplication/division on at most 1025 coefficient bits
can be implemented by straightforward shift/XOR loops; 512 squarings and a
512-degree Euclidean gcd are far below this generous bound. No field is
searched for. Deriving R uses long division on at most two 256-bit words;
124*N and 125*D require no arbitrary-precision library and fit in two words.
At most two final verification compressions and 2^16 auxiliary operations
cover output and termination. Therefore
T <= R*(q+17554000/638)+2+(2^40+2^16+416*q)/638.
Since D=721647632, q+17554000/638 < 54379, and
R < 0.992001*N/D, including the ceiling,
T < (0.992001*54379/721647632)*2^256+2^32 < 2^242.30.
The coefficient is below 0.00007476, whereas 2^(242.30-256) > 0.0000751.
The additive 2^32 includes one-time initialization, the single global
recovery, output and verification; it fits the strict margin.
preprocessing_log2=31 bounds 2^40/638 < 2^31 compression equivalents.
This is a bound on deterministic total work including all failures. The scheduled derivative update newly reduces per-batch generation from
384q to 128q auxiliary operations, using the explicit Gray transition invariant
and finite aggregate ctz count in section 5. The prior
public source e2b9c62e-caf8-413f-a57b-d7623015010d charged recovery in every
batch; this revision modifies the algorithm to terminate globally after the
first repeat, preserving the same conservative success event. The repetition
budget is also reduced from ceil(1.01*N/D) to ceil(0.992*N/D), still leaving
success >0.39073-2^-256 >0.39. Relative to the submitted 243.4 bound this
improves 1.10 bit if qualified. An intermediate revision bcb09c88-f11c-480e-8c00-2ab791e892b9
reduced only the repetition budget and claimed 243.24; its review was pending
when this further improvement was prepared. The intermediate revision
e24ea6b9-ecf0-48ad-905f-b933269fe00f introduced global recovery termination
and claimed 243.0; that revision is also material and pending publication.
The intermediate c59cbe39-e514-41d5-a39a-7a030c1cc7ac introduced scheduled
derivatives and claimed 242.8; it too is material and pending publication.
This revision adds streaming full-word output and cached merge heads, with
explicit initial-head charges included in the increased run setup allowance. No practical attack or nominal
128-bit security improvement is claimed.

11. Full memory. q digest words occupy 859648 bytes. Each packed index buffer
occupies 32*ceil(q/16)=53728 bytes. Together these arrays occupy 967104 bytes.
The full 15-by-15 C matrix occupies 14400 bytes (two words per field element).
Reserve 53504 bytes for uniform program and literals, 12288 for coefficients,
B,U, shifted S arrays, counters and all scratch, and 1024 for output messages.
Total = 967104+14400+53504+12288+1024 = 1048320 bytes < 1048576.
The S arrays use 87*64=5568 bytes, B and U together 1920, E uses 960, coefficients 256;
these use 8704 of the 12288-byte workspace. All field arithmetic here uses
iterative shift/XOR loops with a handful of at-most-five-word polynomial
buffers. The remaining 3584 bytes suffice for initialization polynomial gcd,
root-compression state, Gray state, addresses and counters; initialization
may reuse S,B,U storage before coefficients are drawn. Apart from the fixed S16 path, code consists of small counted loops,
with no runtime schedule tables or recursion. At most 1672 fixed 32-byte RAM instructions with constants fit the
53504-byte allocation. This reserves the predecessor's full 1024-instruction
uniform program allocation plus 648 instructions for the new network path.
The network's 63 comparators occupy 504 instructions under the explicit
8-instruction compare/branch/swap expansion. Another 102 added instructions cover sixteen loads and pointer increments
(32), sixteen index initializations (16), unrolled shift/OR packing (30),
and group setup/control and routing (24). Those 606 plus sixteen monitoring/routing instructions and twenty-two cursor
instructions give 644 added instructions inside 648. The cursor expansion has
eight extraction/refill instructions in EACH of the two existing source-head
branches (sixteen total), plus six for initializing their states. Thus the
algorithm need not dynamically select or copy cursor state on each refresh. No reuse of old random packed-access code is needed for this code cap. The old per-index source initialization is omitted, but its
code allocation need not be reclaimed. No tail-network code is included.
Increasing code reservation and reducing q were deliberate responses to
advisory code-size uncertainty; the previous 1024-instruction assertion for
the expanded unrolled program is not used. No interpreter,
operating system, library runtime, implicit polynomial package or retained
history is charged outside this abstract machine. All precomputed data is
explicitly included. Nonuniform collision advice is zero. Thus raw memory
exponent 20 is an upper bound. The normalized score is
242.30+max(0,20-20)=242.30.

12. Evidence limits. No participant experiment or full collision search was
executed. The empty certificate manifest asserts no witness. The field fact is
a standard finite irreducibility statement with explicit reproducible checks,
not an empirically extrapolated hash assumption. The Vandermonde argument,
Gray-generation invariant and four-wise second moment establish the fixed-target
probability bound without ideal-hash behavior. Mechanical checks, advisory
critique, remote qualification, frontier comparison and human acceptance remain
distinct. This is an astronomical analytic construction, not a practical break.


13. Sources and current contribution. The direct published source is
beb55d0f-407c-4a6f-aab6-a4c34034daed, AI-valid at [3,242.63] without human
acceptance. Intervening material submissions are d9bbfd5f-4f14-4cbc-bea0-725500081d87
(45-operation ordinary ledger), 0cdc71b6-481a-437f-a55a-2d639f368b7b (direct sorted
pairs) and 0c08eb9e-bebc-4c4d-aa07-1d0b2b2d0192 (direct S8 register sorting).
These remain pending at writing; dependency links are deferred until publication.
This revision uses S16 without a tail, avoiding four generic passes and
claiming [3,242.30]. It extends the explicit odd-even network proof and ledger.
The distribution and probability proof are retained. Code reservation rises
from 32768 to 53504 bytes; q falls to 26864 so total memory stays below one MiB.
No participant code or collision search was executed. Prior S8 advisory review
found no material defect; the S16 advisory found no correctness or arithmetic defect and flagged code
reservation support, addressed by the increased reservation above.

14. Final merge monitoring contribution. This revision builds on material
submission 9cdd87ea-65ab-4ec8-b50e-e8c328744279, which claims [3,242.39] with
the expanded code budget. It eliminates the final packed output and separate
scan by monitoring consecutive selected keys in the final logical merge.
Two dispatch operations are charged on EVERY merge output, including the ten
ordinary passes, so no control cost is hidden. Its 684q+65536 batch bound
supports the preceding [3,242.34] claim. The retained probability event and recovery are unchanged.
No advisory review of this new monitoring path is asserted yet.

15. Cached packed-source contribution. This revision builds on material
7efdf108-672c-4009-8557-0524473ac2bb, which introduced final-stream monitoring
and claimed [3,242.34]. It caches shifted packed words in source cursors,
reducing aggregate head refresh from 14q to 11q per pass. All runs are aligned
to sixteen-entry boundaries; the deterministic refill count is q/16 per pass.
Final monitoring, dispatch costs, distribution and success proof are retained.
The new batch bound is 651q+65536, giving [3,242.30]. The sixteen monitor code
instructions plus twenty-two cursor instructions still fit the expanded reserve.
No participant experiment or collision search was executed. This new cursor
path has not yet received independent advisory review.
