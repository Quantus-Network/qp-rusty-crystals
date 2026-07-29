//! ML-DSA-44 (FIPS 204 category 2) public API.
//!
//! Thin frontend over the const-generic signing core, instantiated at the
//! [`crate::params::ml_dsa_44`] parameter set.

crate::frontend::define_ml_dsa!(crate::params::ml_dsa_44);

#[cfg(test)]
mod tests {
	crate::frontend::basic_variant_tests!(2420, 1312, 2560);
	crate::frontend::adversarial_import_tests!();
}
