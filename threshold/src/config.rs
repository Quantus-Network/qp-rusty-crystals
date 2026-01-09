//! Threshold configuration for ML-DSA-87.
//!
//! This module contains the configuration parameters for threshold signing,
//! including the threshold value (t) and total parties (n).

use crate::error::{validate_threshold_params, ThresholdError, ThresholdResult};

/// Configuration for a threshold signing scheme.
///
/// A (t, n) threshold scheme requires at least t out of n parties to
/// cooperate in order to produce a valid signature.
///
/// # Example
///
/// ```
/// use qp_rusty_crystals_threshold::ThresholdConfig;
///
/// // Create a 2-of-3 threshold scheme
/// let config = ThresholdConfig::new(2, 3).expect("valid parameters");
/// assert_eq!(config.threshold(), 2);
/// assert_eq!(config.total_parties(), 3);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThresholdConfig {
    /// Threshold value (minimum parties required to sign).
    t: u8,
    /// Total number of parties.
    n: u8,
    /// Number of iterations (K parameter from reference implementation).
    k_iterations: u16,
    /// Primary radius parameter for hyperball sampling.
    r: f64,
    /// Secondary radius parameter for hyperball sampling.
    r_prime: f64,
    /// Nu parameter (typically 3.0).
    nu: f64,
}

impl ThresholdConfig {
    /// Create a new threshold configuration.
    ///
    /// # Arguments
    ///
    /// * `t` - Threshold value (minimum parties required to sign)
    /// * `n` - Total number of parties
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `t < 2` (threshold must be at least 2)
    /// - `n > 6` (maximum 6 parties supported)
    /// - `t > n` (threshold cannot exceed total parties)
    /// - The (t, n) combination is not supported
    pub fn new(t: u8, n: u8) -> ThresholdResult<Self> {
        validate_threshold_params(t, n)?;

        // ML-DSA-87 specific parameters based on reference implementation
        let (k_iterations, r, r_prime) = match (t, n) {
            (2, 2) => (3, 503119.0, 503192.0),
            (2, 3) => (4, 631601.0, 631703.0),
            (3, 3) => (6, 483107.0, 483180.0),
            (2, 4) => (4, 632903.0, 633006.0),
            (3, 4) => (11, 551752.0, 551854.0),
            (4, 4) => (14, 487958.0, 488031.0),
            (2, 5) => (5, 607694.0, 607820.0),
            (3, 5) => (26, 577400.0, 577546.0),
            (4, 5) => (70, 518384.0, 518510.0),
            (5, 5) => (35, 468214.0, 468287.0),
            (2, 6) => (5, 665106.0, 665232.0),
            (3, 6) => (39, 577541.0, 577704.0),
            (4, 6) => (208, 517689.0, 517853.0),
            (5, 6) => (295, 479692.0, 479819.0),
            (6, 6) => (87, 424124.0, 424197.0),
            _ => {
                return Err(ThresholdError::InvalidParameters {
                    threshold: t,
                    parties: n,
                    reason: "unsupported threshold configuration for ML-DSA-87",
                })
            }
        };

        Ok(Self {
            t,
            n,
            k_iterations,
            r,
            r_prime,
            nu: 3.0,
        })
    }

    /// Get the threshold value (minimum parties required to sign).
    #[inline]
    pub fn threshold(&self) -> u8 {
        self.t
    }

    /// Get the total number of parties.
    #[inline]
    pub fn total_parties(&self) -> u8 {
        self.n
    }

    /// Get the number of iterations (K parameter).
    #[inline]
    pub fn k_iterations(&self) -> u16 {
        self.k_iterations
    }

    /// Get the primary radius parameter for hyperball sampling.
    #[inline]
    pub(crate) fn r(&self) -> f64 {
        self.r
    }

    /// Get the secondary radius parameter for hyperball sampling.
    #[inline]
    pub(crate) fn r_prime(&self) -> f64 {
        self.r_prime
    }

    /// Get the nu parameter.
    #[inline]
    pub(crate) fn nu(&self) -> f64 {
        self.nu
    }

    /// Check if enough parties are participating for threshold.
    #[inline]
    pub fn has_threshold(&self, num_parties: usize) -> bool {
        num_parties >= self.t as usize
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ThresholdConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ThresholdConfig", 2)?;
        state.serialize_field("threshold", &self.t)?;
        state.serialize_field("total_parties", &self.n)?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ThresholdConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct ConfigData {
            threshold: u8,
            total_parties: u8,
        }

        let data = ConfigData::deserialize(deserializer)?;
        ThresholdConfig::new(data.threshold, data.total_parties).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        assert_eq!(config.threshold(), 2);
        assert_eq!(config.total_parties(), 3);
        assert_eq!(config.k_iterations(), 4);
    }

    #[test]
    fn test_all_valid_configs() {
        let valid_configs = [
            (2, 2),
            (2, 3),
            (3, 3),
            (2, 4),
            (3, 4),
            (4, 4),
            (2, 5),
            (3, 5),
            (4, 5),
            (5, 5),
            (2, 6),
            (3, 6),
            (4, 6),
            (5, 6),
            (6, 6),
        ];

        for (t, n) in valid_configs {
            let config = ThresholdConfig::new(t, n);
            assert!(config.is_ok(), "Config ({}, {}) should be valid", t, n);
        }
    }

    #[test]
    fn test_invalid_threshold_too_small() {
        let result = ThresholdConfig::new(1, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_too_many_parties() {
        let result = ThresholdConfig::new(3, 7);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_threshold_exceeds_parties() {
        let result = ThresholdConfig::new(5, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_has_threshold() {
        let config = ThresholdConfig::new(3, 5).unwrap();
        assert!(!config.has_threshold(2));
        assert!(config.has_threshold(3));
        assert!(config.has_threshold(5));
    }
}
