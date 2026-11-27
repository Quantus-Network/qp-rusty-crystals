use core::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum KeyParsingError {
	BadSecretKey,
	BadPublicKey,
}

impl fmt::Display for KeyParsingError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

impl core::error::Error for KeyParsingError {}

#[derive(Debug, PartialEq, Eq)]
pub enum SignatureError {
	ContextTooLong,
	BadDigestLength,
}

impl fmt::Display for SignatureError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

impl core::error::Error for SignatureError {}
