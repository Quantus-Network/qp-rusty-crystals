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

#[derive(Debug)]
pub enum SignatureError {
	ContextTooLong,
}

impl Display for SignatureError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let str = match self {
			SignatureError::ContextTooLong => "ContextTooLong",
		};
		write!(f, "{str}")
	}
}
