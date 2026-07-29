//! ML-DSA-65 (FIPS 204 category 3) public API.
//!
//! Thin frontend over the const-generic signing core, instantiated at the
//! [`crate::params::ml_dsa_65`] parameter set.

crate::frontend::define_ml_dsa!(crate::params::ml_dsa_65);

#[cfg(test)]
mod tests {
	crate::frontend::basic_variant_tests!(3309, 1952, 4032);
	crate::frontend::adversarial_import_tests!();
}
