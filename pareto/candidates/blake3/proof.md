# Four-wise independent message regeneration for complete BLAKE3-r3

1. Scope and sources. This is an unconditional generic finite construction in
the stipulated classical word RAM, not practical reduced-round cryptanalysis.
It improves storage by regenerating 64-byte messages from four random field
coefficients instead of retaining all messages. Four-wise independence replaces
full independence within each batch; a second-moment argument replaces the old
elementary-symmetric-polynomial argument. Independent batches are retained.
The direct starting source is submission e2b9c62e-caf8-413f-a57b-d7623015010d.
This revision additionally terminates the entire attack after the first digest-repeat
recovery, even if that recovery finds only identical messages. Thus at most one
regeneration pass is charged globally rather than once in every batch.
The raw time claim is 243.0, memory 20, success probability 0.39. This does not
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
Set q=27400, k=15, N=2^256, D=q(q-1),
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
Initially x=0, current message v=a0, and derivative vectors Di=Bi. When the Gray
sequence flips bit i, update v <- v XOR Di, then for every j=0,...,14 update
Dj <- Dj XOR Cij. The invariant is
Di=Bi+sum_(j != i) Cij*xj; it is unaffected by xi itself. Therefore v changes
by exactly the polynomial's bit-i finite difference, and updating D restores
the invariant at the new x. The transition j to j+1 flips bit ctz(j+1).
Compute this by at most 14 right shifts and low-bit tests, with a simple loop;
there is no unpriced count-trailing-zeros instruction. No transition after the
last message is needed. This generates the exact four-wise family in section 4.

6. Batch algorithm. Allocate q digest words only; messages are not stored.
Generate v for each j as above, compute F(v), and store digest[j]. Initialize
packed index A[j]=j. Sort indices using bottom-up merging with two packed
16-bit buffers A,B and unsigned complete digest keys. For widths
1,2,4,...,16384, merge adjacent sorted runs into the other buffer, using the
left input on ties, avoiding reads from exhausted runs, and swap bases after
each full pass. Fifteen passes suffice. Scan consecutive sorted digests until
the FIRST equal-digest run is found. If there is no repeat, this batch fails.

7. Bounded recovery. Regenerate the first repeated-digest run's representative
message P(x(s)) once by direct Horner evaluation. Then regenerate all q messages
in a single Gray-order pass using retained B,C and original a0, resetting D=B.
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
is missed by the scan, and only distinct full-message equality is accepted.

8. Fixed-target second moment. For independent uniform single messages write
p_y=Pr[F(M)=y], p2=sum p_y^2, p3=sum p_y^3. Regardless of this fixed function,
p2>=1/N by Cauchy-Schwarz and p3<=p2^(3/2) by the monotonicity of finite l_p
norms. Let Z count digest-equal unordered pairs among q generated messages.
Four-wise independence gives the EXACT moments
lambda=E[Z]=D*p2/2,
E[Z^2]=lambda+6*choose(q,3)*p3+6*choose(q,4)*p2^2.
Terms correspond to identical pairs, pairs sharing one index, and disjoint
pairs; no higher independence is used. At q=27400,
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
Packed 16-bit reads cost at most 9 operations: word/cell indices, scaling,
base addition, load, shift and mask. Packed writes cost at most 16, including
read-modify-write masking and full address arithmetic. Dereferencing a digest
from index t costs at most 3 (t<<5, base add, load). Even allowing 5 per digest,
two merge candidate accesses cost at most 28. Packed output write costs 16,
comparison/choice 4, pointer increments, exhausted-run tests and loop controls
16, totaling 64 per output element per pass. There are exactly 15q outputs.
Run setup uses at most 64 per run. Summing ceil(q/(2w)) over fifteen widths
is less than q+15, so 64q plus fixed overhead covers it.

Generation has a 384-operation-per-message allowance. Derivative updates
traverse one contiguous C row and D sequentially. For each of fifteen elements,
load two C words (two loads, one address increment for high word), load two D
words similarly, XOR two words, store two words, advance both pointers and loop:
at most 16 operations, 240 total. Derive the flipped index by at most 14
iterations of low-bit test/branch, shift and counter increment, at most 64
operations. Load Di, update v and initialize row pointers in at most 24.
The remaining 56 cover message-to-root input setup around the already charged
compression, digest store, packed A write, and outer loop control. Field
coefficients are eight random words PER BATCH, included below. A final
unneeded Gray transition may simply be omitted; charging q transitions is safe.
The regeneration pass costs at most 416q operations: the same at-most-384
message generation, plus 32 for loading/looking up its stored digest,
comparison with the chosen digest, full two-word message comparison and loop
control. It needs no q additional compressions: stored digest[j] is exact,
and final verification is separately charged once on successful recovery.
Only one regeneration pass is ever executed over the entire attack, because
any repeat triggers global termination after recovery. Charge its 416q
operations once in section 10, instead of to every batch.
Sorting scan uses at most 64q including packed reads and digest loads.

Per-batch fixed work is at most 65536 operations: prepare shifted-coefficient
arrays and C,B (under 16384 operations, using 84 X steps and 225 short
constructions), sample coefficients, initialize/reset D and v, pass swaps and
extra run setups, choose the first repeated digest, and regenerate its one
representative. For the latter, x is a polynomial with at most 15 coefficients,
so multiplying a field element by x is done in at most 15 shift/reduction and
conditional-XOR iterations, under 512 operations. Horner evaluation uses three
such products and three XORs; 4096 operations comfortably suffice. Coefficients
and tables are freshly rebuilt in EVERY batch; no independent-batch setup is
amortized away. Shifted S arrays may be overwritten after C,B preparation.
Thus
W_batch <= (15*64+64+64+384)*q+65536
        = 1472*q+65536 = 40398336 auxiliary operations.
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
T <= R*(q+40398336/638)+2+(2^40+2^16+416*q)/638.
Since D=750732600, q+40398336/638 < 90720, and
R < 0.992001*N/D, including the ceiling,
T < (0.992001*90720/750732600)*2^256+2^32 < 2^243.0.
The coefficient is below 0.00011988, whereas 2^-13 = 0.0001220703125.
The additive 2^32 includes one-time initialization, the single global
recovery, output and verification; it fits the strict margin.
preprocessing_log2=31 bounds 2^40/638 < 2^31 compression equivalents.
This is a bound on deterministic total work including all failures. The prior
public source e2b9c62e-caf8-413f-a57b-d7623015010d charged recovery in every
batch; this revision modifies the algorithm to terminate globally after the
first repeat, preserving the same conservative success event. The repetition
budget is also reduced from ceil(1.01*N/D) to ceil(0.992*N/D), still leaving
success >0.39073-2^-256 >0.39. Relative to the submitted 243.4 bound this
improves 0.4 bit if qualified. An intermediate revision bcb09c88-f11c-480e-8c00-2ab791e892b9
reduced only the repetition budget and claimed 243.24; its review was pending
when this further improvement was prepared. No practical attack or nominal
128-bit security improvement is claimed.

11. Full memory. q digest words occupy 876800 bytes. Each packed index buffer
occupies 32*ceil(q/16)=54816 bytes. Together these arrays occupy 986432 bytes.
The full 15-by-15 C matrix occupies 14400 bytes (two words per field element).
Reserve 32768 bytes for uniform program and literals, 12288 for coefficients,
B,D, shifted S arrays, counters and all scratch, and 1024 for output messages.
Total = 986432+14400+32768+12288+1024 = 1046912 bytes < 1048576.
The S arrays use 87*64=5568 bytes, B and D together 1920, coefficients 256;
these use 7744 of the 12288-byte workspace. All field arithmetic here uses
iterative shift/XOR loops with a handful of at-most-five-word polynomial
buffers. The remaining 4544 bytes suffice for initialization polynomial gcd,
root-compression state, Gray state, addresses and counters; initialization
may reuse S,B,D storage before coefficients are drawn. Code consists of small
counted loops, not unrolled tables or recursion. At most 1024 fixed 32-byte
RAM instructions with constants fit the 32768-byte allocation. No interpreter,
operating system, library runtime, implicit polynomial package or retained
history is charged outside this abstract machine. All precomputed data is
explicitly included. Nonuniform collision advice is zero. Thus raw memory
exponent 20 is an upper bound. The normalized score is
243.0+max(0,20-20)=243.0.

12. Evidence limits. No participant experiment or full collision search was
executed. The empty certificate manifest asserts no witness. The field fact is
a standard finite irreducibility statement with explicit reproducible checks,
not an empirically extrapolated hash assumption. The Vandermonde argument,
Gray-generation invariant and four-wise second moment establish the fixed-target
probability bound without ideal-hash behavior. Mechanical checks, advisory
critique, remote qualification, frontier comparison and human acceptance remain
distinct. This is an astronomical analytic construction, not a practical break.

