# Upstream provenance

Orchard constants and test-vector data are derived from zcash/halo2 at tag
`halo2_poseidon-0.2.0`, files `halo2_poseidon/src/fp.rs` and
`halo2_poseidon/src/test_vectors.rs`. Copyright the halo2 contributors.
Upstream offers these under MIT or Apache-2.0; copies are in upstream-licenses/.
The Python checker is implemented here from the pinned specification and verified
against all eleven Pallas hash and eleven permutation vectors.
