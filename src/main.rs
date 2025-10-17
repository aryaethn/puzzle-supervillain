use ark_bls12_381::{g2::Config, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    AffineRepr, CurveGroup,
};
use ark_ff::field_hashers::DefaultFieldHasher;

use ark_serialize::{CanonicalDeserialize, Read};

use prompt::{puzzle, welcome};

use sha2::Sha256;
use std::fs::File;
use std::io::Cursor;
use std::ops::{Mul, Neg};

use ark_std::{rand::SeedableRng, UniformRand, Zero};

fn derive_point_for_pok(i: usize) -> G2Affine {
    let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(20399u64);
    G2Affine::rand(rng).mul(Fr::from(i as u64 + 1)).into()
}

#[allow(dead_code)]
fn pok_prove(sk: Fr, i: usize) -> G2Affine {
    derive_point_for_pok(i).mul(sk).into()
}

fn pok_verify(pk: G1Affine, i: usize, proof: G2Affine) {
    assert!(Bls12_381::multi_pairing(
        &[pk, G1Affine::generator()],
        &[derive_point_for_pok(i).neg(), proof]
    )
    .is_zero());
}

fn hasher() -> MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Config>> {
    let wb_to_curve_hasher =
        MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Config>>::new(
            &[1, 3, 3, 7],
        )
        .unwrap();
    wb_to_curve_hasher
}

#[allow(dead_code)]
fn bls_sign(sk: Fr, msg: &[u8]) -> G2Affine {
    hasher().hash(msg).unwrap().mul(sk).into_affine()
}

fn bls_verify(pk: G1Affine, sig: G2Affine, msg: &[u8]) {
    assert!(Bls12_381::multi_pairing(
        &[pk, G1Affine::generator()],
        &[hasher().hash(msg).unwrap().neg(), sig]
    )
    .is_zero());
}

fn from_file<T: CanonicalDeserialize>(path: &str) -> T {
    let mut file = File::open(path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    T::deserialize_uncompressed_unchecked(Cursor::new(&buffer)).unwrap()
}

fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);

    let public_keys: Vec<(G1Affine, G2Affine)> = from_file("public_keys.bin");

    public_keys
        .iter()
        .enumerate()
        .for_each(|(i, (pk, proof))| pok_verify(*pk, i, *proof));

    let new_key_index = public_keys.len();
    let message = b"aryaethn";

    /* Enter solution here */

    // Rogue key attack: Create a malicious key that cancels all existing keys
    
    // Step 1: Compute new_key = -Σ(pk_i)
    // This will make the aggregate key equal to zero
    let sum_of_pks = public_keys
        .iter()
        .fold(G1Projective::zero(), |acc, (pk, _)| acc + pk);
    let new_key = sum_of_pks.neg().into_affine();
    
    // Step 2: Exploit malleability to create a valid PoP without knowing the secret key
    // For index i, PoP verifies: e(pk_i, (i+1)*G2) = e(G1, proof_i)
    // For our new key at index n: e(new_key, (n+1)*G2) = e(G1, new_proof)
    // Since new_key = -Σ(pk_i), we have:
    // e(-Σ(pk_i), (n+1)*G2) = e(G1, new_proof)
    // = Π e(pk_i, G2)^(-(n+1))
    // = Π e(G1, proof_i/(i+1))^(-(n+1))
    // = e(G1, Σ(-(n+1)/(i+1) * proof_i))
    // Therefore: new_proof = Σ(-(n+1)/(i+1) * proof_i)
    
    let n = new_key_index as u64;
    let new_proof = public_keys
        .iter()
        .enumerate()
        .fold(G2Projective::zero(), |acc, (i, (_, proof))| {
            let i_plus_1 = Fr::from((i as u64) + 1);
            let n_plus_1 = Fr::from(n + 1);
            let coefficient = -(n_plus_1 / i_plus_1); // -(n+1)/(i+1)
            acc + proof.mul(coefficient)
        })
        .into_affine();
    
    // Step 3: Since aggregate_key = new_key + Σ(pk_i) = 0,
    // any signature on the zero point is valid, which is just zero!
    let aggregate_signature = G2Affine::zero();

    /* End of solution */

    pok_verify(new_key, new_key_index, new_proof);
    let aggregate_key = public_keys
        .iter()
        .fold(G1Projective::from(new_key), |acc, (pk, _)| acc + pk)
        .into_affine();
    bls_verify(aggregate_key, aggregate_signature, message);
    println!("Puzzle Solved!✅");
}

const PUZZLE_DESCRIPTION: &str = r"
Bob has been designing a new optimized signature scheme for his L1 based on BLS signatures. Specifically, he wanted to be able to use the most efficient form of BLS signature aggregation, where you just add the signatures together rather than having to delinearize them. In order to do that, he designed a proof-of-possession scheme based on the B-KEA assumption he found in the the Sapling security analysis paper by Mary Maller [1]. Based the reasoning in the Power of Proofs-of-Possession paper [2], he concluded that his scheme would be secure. After he deployed the protocol, he found it was attacked and there was a malicious block entered the system, fooling all the light nodes...

[1] https://github.com/zcash/sapling-security-analysis/blob/master/MaryMallerUpdated.pdf
[2] https://rist.tech.cornell.edu/papers/pkreg.pdf
";
