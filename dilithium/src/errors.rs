use core::{fmt, fmt::Display};

#[derive(Debug)]
pub enum KeyParsingError {
	BadSecretKey,
	BadPublicKey,
	BadKeypair,
}

impl Display for KeyParsingError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let str = match self {
			KeyParsingError::BadSecretKey => "BadSecretKey",
			KeyParsingError::BadPublicKey => "BadPublicKey",
			KeyParsingError::BadKeypair => "BadKeypair",
		};
		write!(f, "{str}")
	}
}

#[cfg(not(feature = "no_std"))]
impl std::error::Error for KeyParsingError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		None
	}
}
