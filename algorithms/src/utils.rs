use crate::types::BigInt;
use crate::types::Powm;
use crate::types::{Integer, Modulo, One, Samplable, Zero};

use std::borrow::Borrow;

/// Finds a generator of  a cyclic group of order n
/// using known factorization of n.
///
/// See "Handbook of applied cryptography", algorithm 4.80
pub fn sample_generator_from_cyclic_group(
    modulo: &BigInt,
    order: &BigInt,
    order_factorization: &[&BigInt],
) -> BigInt {
    let One = BigInt::one();
    loop {
        let alpha = BigInt::sample_below(modulo);
        if !order_factorization
            .iter()
            .any(|&x| alpha.powm_sec(&(order / x), modulo) == One)
        {
            return alpha;
        }
    }
}

/// Solves the system of simultaneous congruences (CRT) with Gauss' algorithm
///
/// See "Handbook of applied cryptography", algorithm 2.121
pub fn crt_solver(reminders: &[&BigInt], moduli: &[&BigInt]) -> BigInt {
    let n = moduli.iter().fold(BigInt::one(), |x, &ni| x * ni);
    let mut result = BigInt::zero();
    for (&ai, &ni) in reminders.iter().zip(moduli) {
        let Ni: BigInt = n.borrow() / ni;
        let Mi: BigInt = BigInt::mod_inv(&Ni, ni).unwrap();
        result += (ai * Ni * Mi) % n.borrow();
    }
    result % n
}

/// Samples a generator from RSA group modulo product of two safe primes
///
/// Samples elements from two cyclic subgroups modulo prime p = (P-1)/2.
/// Finds the generator using CRT
///
pub fn sample_generator_of_rsa_group(safe_p: &BigInt, safe_q: &BigInt) -> BigInt {
    let One = &BigInt::one();
    let Two = &BigInt::from(2);

    let p_prim = (safe_p - One) / Two;
    let q_prim = (safe_q - One) / Two;

    // find generators in prime order subgroups of groups modulo safe_p and safe_q
    let g_p = sample_generator_of_cyclic_subgroup(safe_p, &p_prim);
    let g_q = sample_generator_of_cyclic_subgroup(safe_q, &q_prim);
    crt_solver(&[&g_p, &g_q], &[safe_p, safe_q])
}

/// Sample a generator from cyclic subgroup of the group modulo safe prime
///
/// Samples an element from cyclic subgroup of $` Z^{*}_p `$ of order $` p' `$
/// where $` p,p' `$ are prime and $` p' | (p-1) `$. As the group is cyclic, the element is the generator.
///
/// See "Introduction to modern cryptography", 2nd ed , Algorithm 8.65
pub fn sample_generator_of_cyclic_subgroup(p: &BigInt, p_prim: &BigInt) -> BigInt {
    const MAX_ITERATIONS_IN_REJECTION_SAMPLING: usize = 256;
    let p_minus_one = p - &BigInt::one();
    if p_prim.divides(&p_minus_one) {
        let exp = &p_minus_one.div_floor(p_prim);
        for _ in 0..MAX_ITERATIONS_IN_REJECTION_SAMPLING {
            let h = BigInt::sample_below(p);
            if h != BigInt::one() {
                return h.powm_sec(exp, p);
            }
        }
        unreachable!(
            "rejection sampling exceeded {} iterations in sample_generator_from_cyclic_subgroup()",
            MAX_ITERATIONS_IN_REJECTION_SAMPLING
        );
    } else {
        panic!("incorrect input for sampling a generator of the subgroup");
    }
}

/// return true if every element of the collection beta is in the collection alpha  ( beta is subset of alpha  )
/// both collection have to be sorted beforehand
/// returns true if beta is empty
pub fn is_beta_subset_of_alpha<It>(mut alpha_it: It, mut beta_it: It) -> bool
where
    It: Iterator,
    It::Item: Copy + PartialOrd,
{
    if let Some(b) = beta_it.next() {
        while let Some(a) = alpha_it.next() {
            if a > b {
                return false;
            }
            if a == b {
                return is_beta_subset_of_alpha(alpha_it, beta_it);
            }
        }
        return false;
    }
    true
}
