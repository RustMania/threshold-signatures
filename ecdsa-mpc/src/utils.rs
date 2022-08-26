use crate::types::GE;

pub fn is_valid_curve_point(pk: &GE) -> bool {
    GE::from_bytes(&pk.to_bytes(false)).is_ok()
}

/// returns true if all elements of a collection mapped through f() are equal
pub fn all_mapped_equal<It, F, V>(mut it: It, f: F) -> bool
where
    It: Iterator + Sized,
    F: Fn(It::Item) -> V,
    V: PartialEq,
{
    match it.next() {
        None => true,
        Some(item) => {
            let v = f(item);
            it.map(f).all(|vv| v == vv)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_valid_curve_point;
    use crate::types::{BigInt, FE, GE};
    use crate::types::{Converter, Samplable};
    use std::ops::Deref;

    fn xy_to_key_slice(x: &BigInt, y: &BigInt) -> Vec<u8> {
        let mut v = vec![4 as u8];
        let mut raw_x: Vec<u8> = Vec::new();
        let mut raw_y: Vec<u8> = Vec::new();

        let x_vec = BigInt::to_bytes(x);
        let y_vec = BigInt::to_bytes(y);
        raw_x.extend(vec![0u8; 32 - x_vec.len()]);
        raw_x.extend(x_vec);

        raw_y.extend(vec![0u8; 32 - y_vec.len()]);
        raw_y.extend(y_vec);

        v.extend(raw_x);
        v.extend(raw_y);
        v
    }

    #[test]
    fn pk_utilities() {
        let pk = GE::generator() * FE::random();

        let bytes = pk.to_bytes(false);
        let ppk = GE::from_bytes(&bytes);
        assert!(ppk.is_ok());
        let ppk = ppk.unwrap();
        assert_eq!(pk, ppk);

        assert!(is_valid_curve_point(&pk));

        let xpk = xy_to_key_slice(
            &BigInt::sample_below(&FE::group_order()),
            &BigInt::sample_below(&FE::group_order()),
        );

        let xppk = GE::from_bytes(xpk.as_slice());
        assert!(xppk.is_err());
    }

    #[test]
    fn pk_comparison() {
        let pk = GE::generator() * FE::random();

        let ppk = pk.clone();
        assert!(pk == ppk);

        let p_addr = &pk as *const _;
        let pp_addr = &ppk as *const _;
        assert_ne!(p_addr, pp_addr);
    }

    #[test]
    fn pk_conversion() {
        let pk = GE::generator() * FE::random();
        let bytes = pk.to_bytes(true);
        let ge = GE::from_bytes(bytes.deref());
        assert!(ge.is_ok());
        assert_eq!(pk, ge.unwrap());
    }

    #[test]
    fn test_subsets() {
        use algorithms::utils::is_beta_subset_of_alpha;
        let alpha = vec![1, 2, 3, 5, 6, 7];

        assert!(is_beta_subset_of_alpha(alpha.iter(), vec![].iter()));
        assert!(is_beta_subset_of_alpha(alpha.iter(), vec![1].iter()));
        assert!(is_beta_subset_of_alpha(alpha.iter(), vec![2].iter()));
        assert!(is_beta_subset_of_alpha(alpha.iter(), vec![1, 2, 3].iter()));
        assert!(is_beta_subset_of_alpha(
            alpha.iter(),
            vec![1, 2, 3, 5].iter()
        ));
        assert!(is_beta_subset_of_alpha(
            alpha.iter(),
            vec![2, 3, 5, 6].iter()
        ));
        assert!(is_beta_subset_of_alpha(
            alpha.iter(),
            vec![3, 5, 6, 7].iter()
        ));
        assert!(!is_beta_subset_of_alpha(
            alpha.iter(),
            vec![0, 1, 2, 3].iter()
        ));
        assert!(!is_beta_subset_of_alpha(
            alpha.iter(),
            vec![1, 2, 3, 4].iter()
        ));
        assert!(!is_beta_subset_of_alpha(
            alpha.iter(),
            vec![2, 3, 4, 5].iter()
        ));
        assert!(!is_beta_subset_of_alpha(alpha.iter(), vec![4].iter()));
        assert!(!is_beta_subset_of_alpha(alpha.iter(), vec![4, 5].iter()));
    }
}
